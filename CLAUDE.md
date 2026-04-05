# EspreSSHo — Project Context

## Overview

EspreSSHo is a hardware-backed SSH agent and Git commit signing system built on JavaCard smart cards. The project has two components:

- **Mokapot** — the JavaCard applet running on the card
- **Barista** — the Go host-side SSH agent that talks to the card

The core design goal is that private keys never leave the card. All signing operations are performed on-card; the host only ever sees signatures.

---

## Mokapot (JavaCard Applet)

### Target Platform

- JavaCard 3.2.0v25.1 / SDK25 (targeting JavaCard 3.0.5 compatibility)
- ECC P-256 (`ALG_EC_FP`, 256-bit)
- Standard JavaCard API only — no third-party dependencies
- Applet AID: CA:FE:4D:6F:6B:61

### Key Storage

Up to 4 ECC P-256 keypairs stored in EEPROM. Each slot has:

- A `KeyPair` object (public + private `ECKey`)
- A `byte` of flags (see below)

### Card Lifecycle

After installation the card is **uninitialized**. Only SELECT and `INS_CARD_INIT` (0x7F) are accepted. Every other instruction returns `SW_SECURITY_STATUS_NOT_SATISFIED` (0x6982) until `CARD_INIT` has been called and set `initialized = true` in EEPROM.

`INS_RESET_CARD` (0x7B) is the two-phase nuclear reset that returns the card to the uninitialized state without requiring any credentials. It is the escape hatch for permanent lockout or card handoff scenarios.

### PIN

Uses `javacard.framework.OwnerPIN`. A single PIN protects the card with:

- No default PIN — credentials are set by `INS_CARD_INIT` at first use
- Configurable max tries (default 3) after which the PIN is blocked
- `isValidated()` resets on card deselect/power off — each session requires fresh PIN entry
- A PUK (`OwnerPIN`) for unblocking, using `resetAndUnblock()`
- PIN change via `INS_SET_PIN` (0x7E) requires presenting the old PIN first

### Per-Key Flags (1 byte per slot)

```
 7       6  5  4    3        2  1  0
┌───────┬──────────┬─────────┬──────┐
│ REQ   │ TIMEOUT  │ ERASE   │ RES  │
│ PIN   │ (0–7 min)│ ON LOCK │      │
└───────┴──────────┴─────────┴──────┘
```

| Bits | Name                 | Description                                                             |
| ---- | -------------------- | ----------------------------------------------------------------------- |
| 7    | `FLAG_REQUIRE_PIN`   | Require PIN validation before signing with this key                     |
| 6–4  | `FLAG_TIMEOUT`       | PIN timeout in minutes (0 = session-scoped only, 1–7 = literal minutes) |
| 3    | `FLAG_ERASE_ON_LOCK` | Erase this key's material when the PIN becomes blocked                  |
| 2–0  | Reserved             |                                                                         |

Constants:

```java
static final byte FLAG_REQUIRE_PIN   = (byte)0x80;
static final byte FLAG_TIMEOUT_MASK  = (byte)0x70;
static final byte FLAG_TIMEOUT_SHIFT = (byte)4;
static final byte FLAG_ERASE_ON_LOCK = (byte)0x08;
```

### APDU Instruction Set

#### Normal operations (0x01–0x08) — require initialized card

All write operations use unified PIN-protected format for security and consistency.

| INS              | Byte   | P1         | P2    | Data                  | Description                                                    |
| ---------------- | ------ | ---------- | ----- | --------------------- | -------------------------------------------------------------- |
| `INS_GEN_KEY`    | `0x01` | slot (0–3) | —     | [PIN_LEN][PIN][FLAGS] | Generate new keypair in slot (requires PIN, fails if occupied) |
| `INS_GET_PUBKEY` | `0x02` | slot (0–3) | —     | —                     | Return raw EC public key (no PIN required)                     |
| `INS_SIGN`       | `0x03` | slot (0–3) | flags | digest (1–128 bytes)  | Sign pre-computed digest, return DER signature                 |
| `INS_LIST_KEYS`  | `0x04` | —          | —     | —                     | Return populated slot bitmap (no PIN required)                 |
| `INS_VERIFY_PIN` | `0x05` | —          | —     | PIN bytes             | Verify PIN for this session                                    |
| `INS_REGEN_KEY`  | `0x06` | slot (0–3) | —     | [PIN_LEN][PIN][FLAGS] | Regenerate keypair in slot (requires PIN, replaces any key)    |
| `INS_CLEAR_KEY`  | `0x07` | slot (0–3) | —     | [PIN_LEN][PIN][FLAGS] | Clear key and flags in slot (requires PIN)                     |
| `INS_GET_FLAGS`  | `0x08` | slot (0–3) | —     | —                     | Return flags byte for slot (no PIN required)                   |

#### Admin block (0x7F–0x7B) — card lifecycle management

| INS                | Byte   | P1         | P2         | Data                        | Description                                                                   |
| ------------------ | ------ | ---------- | ---------- | --------------------------- | ----------------------------------------------------------------------------- |
| `INS_CARD_INIT`    | `0x7F` | PIN length | PUK length | PIN \|\| PUK                | One-time init — sets PIN+PUK, marks card initialized. Fails if already done.  |
| `INS_SET_PIN`      | `0x7E` | old length | —          | old PIN \|\| new PIN        | Change PIN (requires current PIN)                                             |
| `INS_SET_PUK`      | `0x7D` | old length | —          | old PUK \|\| new PUK        | Change PUK (requires current PUK)                                             |
| `INS_UNBLOCK_CARD` | `0x7C` | PUK length | —          | PUK \|\| new PIN            | Unblock blocked PIN using PUK                                                 |
| `INS_RESET_CARD`   | `0x7B` | —          | —          | Phase1: none / Phase2: 16 B | Two-phase factory reset — no credentials required (see below)                 |

### SIGN Instruction Detail

- P2 carries flags mirroring the per-key flags byte (currently `FLAG_REQUIRE_PIN` used to force card-side re-validation)
- Data is a SHA-256 digest (hashing is done on the Go side before sending)
- Returns DER-encoded ECDSA signature
- Signer initialized as `ALG_ECDSA_SHA_256` — card does not re-hash

### Status Words

| SW       | Meaning                                                                                     |
| -------- | ------------------------------------------------------------------------------------------- |
| `0x9000` | Success                                                                                     |
| `0x6982` | Security status not satisfied — PIN failed, card not yet initialized, or wrong reset nonce  |
| `0x6983` | PIN or PUK blocked                                                                          |
| `0x6985` | Key slot already occupied (use `INS_REGEN_KEY`)                                             |
| `0x6A82` | Key slot not found (empty slot)                                                             |
| `0x63Cx` | Wrong PIN/PUK, `x` tries remaining                                                          |

### Unified PIN-Protected Operations

GEN_KEY, REGEN_KEY, and CLEAR_KEY use a unified APDU format for consistency:

```
APDU Format: [PIN_LEN][PIN][FLAGS]
```

- **PIN_LEN**: 1 byte (range: 1-8)
- **PIN**: Variable-length PIN data (1-8 bytes)
- **FLAGS**: Security flags byte (see Flag Constants)

**Examples:**

```
GEN_KEY (0x01) with PIN "1234" and FLAG_REQUIRE_PIN:
00 01 00 00 06 04 31 32 33 34 80

CLEAR_KEY (0x07) with PIN "test" and no flags:
00 07 01 00 06 04 74 65 73 74 00
```

### INS_RESET_CARD Two-Phase Protocol

`INS_RESET_CARD` (0x7B) is a "blow everything away" reset requiring no credentials:

**Phase 1** — no data (`Lc` absent):
```
00 7B 00 00        → 16-byte nonce (stored in CLEAR_ON_DESELECT transient memory)
```

**Phase 2** — data = the 16 bytes returned by Phase 1:
```
00 7B 00 00 10 <16 nonce bytes>    → 90 00 (card wiped, initialized = false)
```

- Deselecting between phases clears the nonce — restart from Phase 1
- Wrong nonce in Phase 2 immediately invalidates the nonce and returns 0x6982
- After success, `INS_CARD_INIT` must be called before any other instruction

### Security Model

**Uninitialized card (before INS_CARD_INIT):**

- Only SELECT and `INS_CARD_INIT` (0x7F) are accepted
- All other instructions return `SW_SECURITY_STATUS_NOT_SATISFIED` (0x6982)

**Read Operations (No PIN Required):**

- GET_PUBKEY: Returns public key for any populated slot
- LIST_KEYS: Returns bitmap of occupied slots
- GET_FLAGS: Returns flags byte for a slot

**Write Operations (PIN Required):**

- GEN_KEY: Creates new key, fails if slot occupied
- REGEN_KEY: Replaces existing key, explicitly sets flags
- CLEAR_KEY: Securely deletes key and clears flags

**Admin Operations:**

- SET_PIN (0x7E): Requires current PIN
- SET_PUK (0x7D): Requires current PUK
- UNBLOCK_CARD (0x7C): Requires PUK
- RESET_CARD (0x7B): Two-phase nonce only — no credentials

**Protection Features:**

- **Slot Protection**: GEN_KEY prevents accidental overwrites
- **Explicit Flags**: All operations set flags from APDU data
- **Transaction Safety**: All operations are atomic
- **PIN Enforcement**: All write operations require PIN verification
- **Initialization Gate**: Uninitialized cards reject everything except CARD_INIT

### ERASE_ON_LOCK Behavior

When the PIN becomes blocked (final failed attempt consumed), any slot with `FLAG_ERASE_ON_LOCK` set has its key material zeroed via `clearKey()`. This is wrapped in a `JCSystem.beginTransaction()` / `commitTransaction()` block to ensure atomicity across a potential power loss. Post-erase, sign attempts on that slot throw `CryptoException.UNINITIALIZED_KEY`.

---

### Dependencies

**Go Dependencies (from go.mod):**

```
github.com/ebfe/scard          // PC/SC smart card bindings
github.com/spf13/cobra         // CLI framework
golang.org/x/crypto/ssh/agent  // SSH agent interface and ServeAgent
golang.org/x/term              // ReadPassword for PIN prompt
```

**JavaCard Test Dependencies (from ivy.xml):**

```
com.github.martinpaljak/jcardengine  // JavaCard applet testing framework
junit/junit                          // Unit testing framework
org.hamcrest/hamcrest-core          // JUnit assertions
```

### SSH Agent Interface

`agent.ServeAgent` (from `x/crypto`) handles the SSH agent wire protocol entirely. Barista only needs to implement:

- `List()` — return public keys from populated card slots
- `Sign()` — forward digest to card, return formatted signature
- Stubs for `Add`, `Remove`, `RemoveAll`, `Lock`, `Unlock`

### Key Structures

```go
type KeySlot struct {
    publicKey   ssh.PublicKey
    flags       byte
    pinVerified bool
    lastPINTime time.Time
}

type CardAgent struct {
    card  scard.Card
    slots [4]KeySlot
}
```

### PIN Handling

PIN entry is internal to the agent — the SSH agent protocol has no PIN concept. PIN prompting uses `SSH_ASKPASS` if set (for GUI environments), falling back to `term.ReadPassword` on the terminal. PIN bytes are zeroed after use with a defer.

`needsPIN(slot int)` logic:

1. If `FLAG_REQUIRE_PIN` not set → false
2. If not yet verified this session → true
3. If timeout bits == 0 → false (session-scoped, already verified)
4. If `time.Since(lastPINTime) > timeout` → true

### Signing Flow

1. Identify slot from public key match
2. Check `needsPIN(slot)` — prompt and verify if needed
3. SHA-256 hash the data on the Go side
4. Transmit SIGN APDU with slot, flags, digest
5. Parse DER response → extract r, s
6. Marshal into SSH wire format (`ecdsa-sha2-nistp256`)
7. Return `*ssh.Signature`

### DER → SSH Signature Marshaling

The card returns a standard DER-encoded ECDSA signature. This needs to be re-encoded into SSH's wire format: a `mpint` r followed by a `mpint` s, wrapped in the standard SSH signature envelope.

### Status Word Handling

```go
var ErrPINBlocked = errors.New("card PIN is blocked — use PUK to unblock")

func parseSW(sw uint16) error {
    switch {
    case sw == 0x9000:
        return nil
    case sw == 0x6983:
        return ErrPINBlocked
    case sw&0xFFF0 == 0x63C0:
        return fmt.Errorf("wrong PIN, %d tries remaining", sw&0x000F)
    default:
        return fmt.Errorf("unexpected SW: %04X", sw)
    }
}
```

On receiving `ErrPINBlocked`, the agent calls `refreshSlots()` to invalidate any in-memory public key cache for erased slots.

### Agent Startup

```go
func main() {
    // 1. Connect to card via PC/SC
    // 2. Select applet by AID
    // 3. Check if card is initialized (try LIST_KEYS; if 0x6982 → prompt CARD_INIT)
    // 4. Enumerate populated slots, cache public keys
    // 5. Listen on Unix socket (e.g. /tmp/barista.sock)
    // 6. Set SSH_AUTH_SOCK
    // 7. Loop: accept conn, go agent.ServeAgent(cardAgent, conn)
}
```

---

## Git Signing

No changes needed to either component. Git SSH signing (available since Git 2.34) goes through `SSH_AUTH_SOCK` identically to SSH auth. Configuration:

```bash
git config --global gpg.format ssh
git config --global user.signingKey "ecdsa-sha2-nistp256 AAAA..."
git config --global commit.gpgSign true
```

Git sends the raw commit buffer; the SSH signing protocol handles hashing. Since Barista hashes on the Go side before sending to the card, ensure the hash is computed over the data as presented by the SSH signing protocol, not double-hashed.

---

## Build Environment

- **Mokapot:** JavaCard 3.2.0v25.1 / SDK25, Java 21+, Apache Ant with ant-javacard plugin
- **Barista:** Go 1.23+, uses cobra CLI framework and scard for PC/SC
- **Card loading:** GlobalPlatformPro (`gp` tool)
- **Build system:** just command runner
- **Platform:** Cross-platform (developed on arm64 macOS)

---

## Project Structure

```
espressoho/
├── mokapot/                  # JavaCard applet
│   ├── build.xml            # Ant build configuration
│   ├── ivy.xml              # Dependency management
│   └── src/
│       ├── main/java/       # Applet source code
│       └── test/java/       # JCardEngine unit tests
└── barista/                  # Go SSH agent
    ├── go.mod               # Go module definition
    ├── main.go              # Entry point
    ├── card/                # PC/SC communication layer
    ├── sshagent/            # SSH agent implementation
    ├── crypto/              # Cryptographic utilities
    └── cmd/                 # Cobra CLI commands
```
