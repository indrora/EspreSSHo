# EspreSSHo Mokapot Applet API Reference

This document provides complete instructions for interacting with the EspreSSHo Mokapot JavaCard applet using PC/SC commands.

## Quick Start

1. **Select the applet** using AID: `CAFE4D6F6B61000100000000000000`
2. **Initialize the card** with `INS_CARD_INIT` (first use only)
3. **Generate or list keys** using the PIN-protected format
4. **Sign data** with a key
5. **Verify signature** on the host

## Applet Identification

- **Package AID**: `CAFE4D6F6B61` ("CafeMoka")
- **Applet AID**: `CAFE4D6F6B61000100000000000000`
- **Default PIN**: none — set by `INS_CARD_INIT` at first use
- **Default PUK**: none — set by `INS_CARD_INIT` at first use

## APDU Command Format

All commands use ISO 7816-4 format:

```
CLA INS P1  P2  [Lc Data] [Le]
00  xx  yy  zz  [nn ...] [ee]
```

- **CLA**: Always `0x00`
- **INS**: Instruction byte (see tables below)
- **P1, P2**: Parameters
- **Lc**: Length of data (if present)
- **Data**: Command data
- **Le**: Expected response length (if needed)

## Command Reference

### Normal Operations (0x01–0x08)

All require the card to have been initialized via `INS_CARD_INIT`.

| Command            | INS    | P1         | P2     | Data Format             | Response           | Description                   |
| ------------------ | ------ | ---------- | ------ | ----------------------- | ------------------ | ----------------------------- |
| **Generate Key**   | `0x01` | slot (0–3) | `0x00` | `[PIN_LEN][PIN][FLAGS]` | 65-byte public key | Create new EC P-256 keypair   |
| **Get Public Key** | `0x02` | slot (0–3) | `0x00` | —                       | 65 bytes           | Uncompressed EC point         |
| **Sign**           | `0x03` | slot (0–3) | flags  | digest (1–128 bytes)    | DER signature      | Sign pre-computed digest      |
| **List Keys**      | `0x04` | `0x00`     | `0x00` | —                       | 1-byte bitmask     | Get populated slots           |
| **Verify PIN**     | `0x05` | `0x00`     | `0x00` | PIN bytes               | —                  | Authenticate user for session |
| **Regenerate Key** | `0x06` | slot (0–3) | `0x00` | `[PIN_LEN][PIN][FLAGS]` | 65-byte public key | Replace existing key          |
| **Clear Key**      | `0x07` | slot (0–3) | `0x00` | `[PIN_LEN][PIN][FLAGS]` | —                  | Delete key and flags          |
| **Get Flags**      | `0x08` | slot (0–3) | `0x00` | —                       | 1-byte flags       | Read per-key flags            |

### Admin Block (0x7F–0x7B)

| Command          | INS    | P1             | P2         | Data                                   | Description                          |
| ---------------- | ------ | -------------- | ---------- | -------------------------------------- | ------------------------------------ |
| **Card Init**    | `0x7F` | PIN length     | PUK length | PIN \|\| PUK                           | One-time init; fails if already done |
| **Set PIN**      | `0x7E` | old PIN length | `0x00`     | old PIN \|\| new PIN                   | Change PIN                           |
| **Set PUK**      | `0x7D` | old PUK length | `0x00`     | old PUK \|\| new PUK                   | Change PUK                           |
| **Unblock Card** | `0x7C` | PUK length     | `0x00`     | PUK \|\| new PIN                       | Unblock blocked PIN                  |
| **Reset Card**   | `0x7B` | `0x00`         | `0x00`     | Phase 1: none / Phase 2: 16-byte nonce | Two-phase factory reset              |

## Status Codes

| Code     | Meaning                                                    |
| -------- | ---------------------------------------------------------- |
| `0x9000` | Success                                                    |
| `0x6982` | Security status not satisfied                              |
| `0x6983` | PIN or PUK blocked                                         |
| `0x6985` | Key slot already occupied (GEN_KEY) — use REGEN_KEY        |
| `0x63Cx` | Wrong PIN/PUK, `x` tries remaining                         |
| `0x6A82` | Key not found in slot                                      |
| `0x6A86` | Incorrect P1/P2 parameters                                 |
| `0x6A80` | Invalid flags (reserved bits set)                          |
| `0x6700` | Wrong length (invalid APDU or PIN length)                  |
| `0x6F00` | Internal error                                             |
| `0x6986` | Command not alowed -- used when card isn't initialized yet |

## Complete Usage Examples

### 1. Select Applet

```
Command: 00 A4 04 00 10 CA FE 4D 6F 6B 61 00 01 00 00 00 00 00 00 00 00
Response: 90 00
```

### 2. Initialize Card (first use only)

PIN "1234" (4 bytes), PUK "12345678" (8 bytes):

> [!abstract] PIN/PUK length
> The PIN and PUK can be each up to 255 bytes long.

```
Command: 00 7F 04 08 0C 31 32 33 34 31 32 33 34 35 36 37 38
         │  │  │  │  │
         │  │  │  │  └── Lc = 4 + 8 = 12
         │  │  │  └───── P2 = PUK length (8)
         │  │  └──────── P1 = PIN length (4)
         │  └─────────── INS (CARD_INIT)
         └────────────── CLA

Response: 90 00
```

### 3. List Available Keys

```
Command: 00 04 00 00
Response: 00 90 00  (no keys present)
```

### 4. Generate Key in Slot 0

```
Command: 00 01 00 00 06 04 31 32 33 34 80
         │  │  │  │  │  │  └─ PIN bytes (1234) ─┘ └─ FLAGS (0x80)
         │  │  │  │  │  └─── PIN length (4)
         │  │  │  │  └────── Data length (6)
         │  │  │  └───────── P2 (reserved)
         │  │  └──────────── P1 (slot 0)
         │  └─────────────── INS (GEN_KEY)
         └────────────────── CLA

Response: 04[64 bytes public key]90 00
```

### 5. Sign a SHA-256 Hash

Pre-compute SHA-256 of your data on the host, then:

```
Command: 00 03 00 00 20 [32 bytes SHA-256 hash]
Response: [DER-encoded ECDSA signature] 90 00
```

### 6. Regenerate Key in Existing Slot

```
Command: 00 06 01 00 06 04 31 32 33 34 00
                                     └─ FLAGS (0x00 = no special flags)
Response: 04[64 bytes new public key]90 00
```

### 7. Clear Key from Slot

```
Command: 00 07 02 00 06 04 31 32 33 34 00
Response: 90 00  (slot 2 now empty)
```

### 8. Change PIN

From "1234" to "5678":

```
Command: 00 7E 04 00 08 31 32 33 34 35 36 37 38
Response: 90 00
```

### 9. Factory Reset (locked out)

```
# Phase 1 — request nonce
Command: 00 7B 00 00 00
Response: [16 nonce bytes] 90 00

# Phase 2 — confirm reset with nonce
Command: 00 7B 00 00 10 [same 16 nonce bytes]
Response: 90 00

# Re-initialize after reset
Command: 00 7F 04 08 0C 31 32 33 34 31 32 33 34 35 36 37 38
Response: 90 00
```

## Key Flags

Each key has configurable behavior flags:

```
Bit 7: FLAG_REQUIRE_PIN (0x80)
  - Set: Require PIN before each signature
  - Clear: PIN verification lasts for session

Bits 6-4: Timeout in minutes (0-7)
  - 0: Session-scoped (until card deselect/power-off)
  - 1-7: Timeout in minutes (host-enforced)

Bit 3: FLAG_ERASE_ON_LOCK (0x08)
  - Set: Erase key if PIN becomes blocked
  - Clear: Keep key when PIN blocked

Bits 2-0: Reserved (must be 0)
```

Common flag combinations:

- `0x80`: Require PIN for every signature
- `0x00`: PIN lasts until card deselect
- `0x88`: Require PIN + erase on lock
- `0x10`: 1-minute timeout

## Python Example

```python
from smartcard.System import readers
from smartcard.util import toHexString
import hashlib

# Connect
reader = readers()[0]
conn = reader.createConnection()
conn.connect()

# Select applet
select_cmd = [0x00, 0xA4, 0x04, 0x00, 0x10,
              0xCA, 0xFE, 0x4D, 0x6F, 0x6B, 0x61,
              0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
resp, sw1, sw2 = conn.transmit(select_cmd)
assert (sw1, sw2) == (0x90, 0x00), f"Select failed: {sw1:02X}{sw2:02X}"

# Initialize card (first use only)
pin = b"1234"
puk = b"12345678"
init_cmd = ([0x00, 0x7F, len(pin), len(puk), len(pin) + len(puk)]
            + list(pin) + list(puk))
resp, sw1, sw2 = conn.transmit(init_cmd)
if (sw1, sw2) == (0x69, 0x82):
    print("Card already initialized")
else:
    assert (sw1, sw2) == (0x90, 0x00), f"Init failed: {sw1:02X}{sw2:02X}"

# Generate key in slot 0 (PIN + flags required)
flags = 0x80  # FLAG_REQUIRE_PIN
gen_cmd = ([0x00, 0x01, 0x00, 0x00, len(pin) + 2]
           + [len(pin)] + list(pin) + [flags])
pubkey_resp, sw1, sw2 = conn.transmit(gen_cmd)
assert (sw1, sw2) == (0x90, 0x00)
print(f"Generated Public Key: {toHexString(pubkey_resp)}")

# Sign something
message = b"Hello, EspreSSHo!"
hash_digest = hashlib.sha256(message).digest()
sign_cmd = [0x00, 0x03, 0x00, 0x00, 0x20] + list(hash_digest)
sig_resp, sw1, sw2 = conn.transmit(sign_cmd)
assert (sw1, sw2) == (0x90, 0x00)
print(f"Signature: {toHexString(sig_resp)}")
```

## Signature Verification

The applet returns ECDSA signatures in DER format. To verify:

1. **Parse DER signature** to extract `r` and `s` values
2. **Verify** using the public key and original message with ECDSA-SHA256

Example DER signature structure:

```
30 [length]           -- SEQUENCE
   02 [r-length] [r]  -- INTEGER r
   02 [s-length] [s]  -- INTEGER s
```

## Error Handling

### PIN Management

- 3 failed PIN attempts → PIN blocked (`0x6983`)
- Use `UNBLOCK_CARD` (`0x7C`) with PUK to unblock and set new PIN
- 5 failed PUK attempts → PUK permanently blocked; use `RESET_CARD`

### Slot Management

- **GEN_KEY Protection**: Returns `0x6985` if slot occupied
- **Solution**: Use `REGEN_KEY` (`0x06`) to replace keys intentionally
- **Atomic Operations**: Key generation and flag setting are transactional

### Uninitialized Card

- All instructions except SELECT and `CARD_INIT` return `0x6986`
- Send `INS_CARD_INIT` (`0x7F`) with your PIN and PUK before any key operations

### Hardware vs Simulator

- **✅ Real Hardware**: All operations work reliably with full P-256 support
- **⚠️ Simulators**: P-256 domain parameters may fail due to environment limitations

## Security Notes

1. **No Default Credentials**: PIN and PUK must be set explicitly via `CARD_INIT`
2. **PIN Protection**: All write operations require PIN verification
3. **Hash on Host**: Send only pre-computed digests to the card, never raw data
4. **Key Isolation**: Each slot operates independently
5. **PUK Backup**: Store PUK securely — it is the PIN recovery method; if PUK is lost, `RESET_CARD` is the only option
6. **Factory Reset**: `RESET_CARD` requires no credentials; protect physical card access
7. **Standards Compliance**: Follows JavaCard 3.0.5 and ISO 7816-4 specifications

## Performance Characteristics

Based on real JavaCard hardware testing:

| Operation            | Performance | Notes                          |
| -------------------- | ----------- | ------------------------------ |
| Card Init            | <50ms       | One-time operation             |
| Key Generation       | ~125ms      | Returns public key immediately |
| Signature Generation | <100ms      | DER-encoded output             |
| PIN Verification     | <50ms       | Session-scoped by default      |
| Public Key Retrieval | <50ms       | 65-byte uncompressed format    |

This completes the API reference for PC/SC interaction with the EspreSSHo Mokapot applet.
