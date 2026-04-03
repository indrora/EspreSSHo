# EspreSSHo — Project Context

## Overview

EspreSSHo is a hardware-backed SSH agent and Git commit signing system built on JavaCard smart cards. The project has two components:

- **Mokapot** — the JavaCard applet running on the card
- **Barista** — the Go host-side SSH agent that talks to the card

The core design goal is that private keys never leave the card. All signing operations are performed on-card; the host only ever sees signatures.

---

## Mokapot (JavaCard Applet)

### Target Platform

- JavaCard 3.0.5 / SDK25
- ECC P-256 (`ALG_EC_FP`, 256-bit)
- Standard JavaCard API only — no third-party dependencies

### Key Storage

Up to 4 ECC P-256 keypairs stored in EEPROM. Each slot has:
- A `KeyPair` object (public + private `ECKey`)
- A `byte` of flags (see below)

### PIN

Uses `javacard.framework.OwnerPIN`. A single PIN protects the card with:
- Configurable max tries (default 3) after which the PIN is blocked
- `isValidated()` resets on card deselect/power off — each session requires fresh PIN entry
- A PUK (`OwnerPIN`) for unblocking, using `resetAndUnblock()`
- PIN change requires presenting the old PIN first

### Per-Key Flags (1 byte per slot)

```
 7       6  5  4    3        2  1  0
┌───────┬──────────┬─────────┬──────┐
│ REQ   │ TIMEOUT  │ ERASE   │ RES  │
│ PIN   │ (0–7 min)│ ON LOCK │      │
└───────┴──────────┴─────────┴──────┘
```

| Bits | Name | Description |
|---|---|---|
| 7 | `FLAG_REQUIRE_PIN` | Require PIN validation before signing with this key |
| 6–4 | `FLAG_TIMEOUT` | PIN timeout in minutes (0 = session-scoped only, 1–7 = literal minutes) |
| 3 | `FLAG_ERASE_ON_LOCK` | Erase this key's material when the PIN becomes blocked |
| 2–0 | Reserved | |

Constants:
```java
static final byte FLAG_REQUIRE_PIN   = (byte)0x80;
static final byte FLAG_TIMEOUT_MASK  = (byte)0x70;
static final byte FLAG_TIMEOUT_SHIFT = (byte)4;
static final byte FLAG_ERASE_ON_LOCK = (byte)0x08;
```

### APDU Instruction Set

| INS | Byte | P1 | P2 | Data | Description |
|---|---|---|---|---|---|
| `INS_GEN_KEY` | `0x01` | slot (0–3) | — | — | Generate new keypair in slot |
| `INS_GET_PUBKEY` | `0x02` | slot (0–3) | — | — | Return raw EC public key |
| `INS_SIGN` | `0x03` | slot (0–3) | flags | SHA-256 digest (32 bytes) | Sign digest, return DER signature |
| `INS_LIST_KEYS` | `0x04` | — | — | — | Return populated slot bitmap |
| `INS_VERIFY_PIN` | `0x05` | — | — | PIN bytes | Verify PIN |
| `INS_CHANGE_PIN` | `0x06` | old PIN length | — | old PIN \|\| new PIN | Change PIN |
| `INS_SET_FLAGS` | `0x07` | slot (0–3) | flags byte | — | Set per-key flags |
| `INS_REGEN_KEY` | `0x08` | slot (0–3) | — | — | Regenerate keypair, returns new pubkey |
| `INS_UNBLOCK_PIN` | `0x09` | PUK length | — | PUK \|\| new PIN | Unblock PIN using PUK |

### SIGN Instruction Detail

- P2 carries flags mirroring the per-key flags byte (currently `FLAG_REQUIRE_PIN` used to force card-side re-validation)
- Data is a SHA-256 digest (hashing is done on the Go side before sending)
- Returns DER-encoded ECDSA signature
- Signer initialized as `ALG_ECDSA_SHA_256` — card does not re-hash

### PIN Failure Status Words

| SW | Meaning |
|---|---|
| `0x9000` | Success |
| `0x6983` | PIN blocked |
| `0x63Cx` | Wrong PIN, `x` tries remaining |

### ERASE_ON_LOCK Behavior

When the PIN becomes blocked (final failed attempt consumed), any slot with `FLAG_ERASE_ON_LOCK` set has its key material zeroed via `clearKey()`. This is wrapped in a `JCSystem.beginTransaction()` / `commitTransaction()` block to ensure atomicity across a potential power loss. Post-erase, sign attempts on that slot throw `CryptoException.UNINITIALIZED_KEY`.

---

## Barista (Go SSH Agent)

### Dependencies

```
golang.org/x/crypto/ssh/agent   // SSH agent interface and ServeAgent
golang.org/x/term               // ReadPassword for PIN prompt
github.com/ebfe/scard           // PC/SC smart card bindings
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
    // 3. Enumerate populated slots, cache public keys
    // 4. Listen on Unix socket (e.g. /tmp/barista.sock)
    // 5. Set SSH_AUTH_SOCK
    // 6. Loop: accept conn, go agent.ServeAgent(cardAgent, conn)
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

- **Mokapot:** JavaCard 3.0.5 / SDK25, Java 20, Gradle with `fr.bmartel.javacard` plugin
- **Barista:** Go (current stable), `go mod`
- **Card loading:** `gp` (GlobalPlatformPro JAR)
- **Platform:** arm64 macOS — no known issues with this stack

---

## Project Structure (Suggested)

```
espressoho/
├── mokapot/                  # JavaCard applet
│   ├── build.gradle
│   └── src/main/java/
│       └── com/espressoho/mokapot/
│           ├── SSHKeyApplet.java
│           ├── ECParams.java       # P-256 curve parameter constants
│           └── APDUConstants.java
└── barista/                  # Go SSH agent
    ├── go.mod
    ├── main.go
    ├── agent.go              # CardAgent implementing ssh/agent.Agent
    ├── card.go               # PC/SC communication, APDU helpers
    ├── pin.go                # PIN prompt, verify, change, PUK
    ├── keys.go               # Public key formatting, DER→SSH marshaling
    └── flags.go              # Flag constants and needsPIN logic
```
