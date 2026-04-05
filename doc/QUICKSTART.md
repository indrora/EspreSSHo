# Quick Start Guide: EspreSSHo Mokapot Applet

This is a condensed guide to get you up and running with the Mokapot applet in 5 minutes.

## What You Need

- JavaCard with the Mokapot applet installed
- PC/SC library (pyscard, PCSC-Lite, etc.)
- Your programming language of choice

### Tested Hardware Platforms
- Real JavaCard hardware (P-256 compatibility, development ready)
- Physical smart card readers via PC/SC
- ⚠️ JavaCard simulators (compatibility mode, ~32% test success)

## The Essentials

**Applet AID**: `CAFE4D6F6B61000100000000000000` ("CafeMoka")
**Default PIN**: none — you set it with `CARD_INIT` (0x7F) on first use
**Default PUK**: none — you set it with `CARD_INIT` (0x7F) on first use
**API Version**: v2.0 (admin block + initialization gate)

## 5-Step Workflow

### 1. Wake Up the Applet
```
SELECT: 00 A4 04 00 10 CA FE 4D 6F 6B 61 00 01 00 00 00 00 00 00 00 00
```

### 2. Initialize the Card (first use only)

A fresh card rejects everything until you call `CARD_INIT`. Set your PIN and PUK here.

```
CARD_INIT: 00 7F 04 08 0C 31 32 33 34 31 32 33 34 35 36 37 38
           │  │  │  │  │  └──── PIN bytes (1234) ──┘ └── PUK bytes (12345678) ─┘
           │  │  │  │  └─────── Lc = PIN len + PUK len = 12
           │  │  │  └────────── P2 = PUK length (8)
           │  │  └───────────── P1 = PIN length (4)
           │  └──────────────── INS (CARD_INIT)
           └─────────────────── CLA

Response: 90 00
```

If the card is already initialized, this returns `69 82`. That's fine — skip to step 3.

### 3. Create a Key
```
GENERATE: 00 01 00 00 06 04 31 32 33 34 80
          │  │  │  │  │  │  └─ PIN bytes (1234) ─┘ └─ FLAGS (0x80)
          │  │  │  │  │  └─── PIN length (4)
          │  │  │  │  └────── Data length (6)
          │  │  │  └───────── P2 (reserved)
          │  │  └──────────── P1 (slot 0)
          │  └─────────────── INS (GEN_KEY)
          └────────────────── CLA

Response: 04[64 bytes public key]90 00  (immediate public key return!)
```

### 4. Sign Something
```bash
# Hash your data with SHA-256 first!
echo "Hello, World!" | openssl dgst -sha256 -binary > hash.bin

# Sign the hash (32-byte SHA-256)
SIGN: 00 03 00 00 20 [32 bytes of hash]
Response: [DER signature] 90 00
```

### 5. Get Public Key (if needed separately)
```
GET PUBKEY: 00 02 00 00
Response: 04 [32-byte X] [32-byte Y] 90 00
```

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
assert (sw1, sw2) == (0x90, 0x00)

# Initialize card (first use — skip if already initialized)
pin = b"1234"
puk = b"12345678"
init_cmd = ([0x00, 0x7F, len(pin), len(puk), len(pin) + len(puk)]
            + list(pin) + list(puk))
resp, sw1, sw2 = conn.transmit(init_cmd)
if (sw1, sw2) not in [(0x90, 0x00), (0x69, 0x82)]:
    raise RuntimeError(f"Card init failed: {sw1:02X}{sw2:02X}")

# Generate key in slot 0 (PIN + flags required)
flags = 0x80  # FLAG_REQUIRE_PIN
gen_cmd = ([0x00, 0x01, 0x00, 0x00, len(pin) + 2]
           + [len(pin)] + list(pin) + [flags])
pubkey_resp, sw1, sw2 = conn.transmit(gen_cmd)
assert (sw1, sw2) == (0x90, 0x00)
print(f"Generated Public Key: {toHexString(pubkey_resp)}")

# Sign something (PIN already verified inline by GEN_KEY above)
message = b"Hello, EspreSSHo!"
hash_digest = hashlib.sha256(message).digest()
sign_cmd = [0x00, 0x03, 0x00, 0x00, 0x20] + list(hash_digest)
sig_resp, sw1, sw2 = conn.transmit(sign_cmd)
assert (sw1, sw2) == (0x90, 0x00)
print(f"Signature: {toHexString(sig_resp)}")
```

## Common Operations

### Fill All 4 Slots
```bash
gp --apdu 00A4040010CAFE4D6F6B61000100000000000000 \
   --apdu 00A004080C31323334313233343536373839  \  # CARD_INIT (first time)
   --apdu 000100000604313233348000              \  # slot 0
   --apdu 000101000604313233348000              \  # slot 1
   --apdu 000102000604313233348000              \  # slot 2
   --apdu 000103000604313233348000                 # slot 3
```

### Replace Existing Key
```bash
# Use REGEN_KEY (0x06) for occupied slots
gp --apdu 00A4040010CAFE4D6F6B61000100000000000000 \
   --apdu 000600000604313233340000                   # slot 0, no flags
```

### Clear a Key
```bash
gp --apdu 00A4040010CAFE4D6F6B61000100000000000000 \
   --apdu 000700000604313233340000                   # clear slot 0
```

### Factory Reset (locked out)
```bash
# Phase 1: get nonce
gp --apdu 00A4040010CAFE4D6F6B61000100000000000000 \
   --apdu 00A4000000                                 # returns 16-byte nonce

# Phase 2: confirm reset with the nonce bytes
gp --apdu 00A40000 10 <nonce bytes here>

# Re-initialize
gp --apdu 00A004080C31323334313233343536373839
```

## Key Features

### Security
- **No Default Credentials**: PIN and PUK are set explicitly on first use
- **Initialization Gate**: Uninitialized cards reject all instructions except CARD_INIT
- **PIN Protection**: All write operations require PIN verification
- **Slot Protection**: GEN_KEY fails if slot occupied (prevents accidental overwrites)
- **Atomic Operations**: Key generation and flag setting are transactional

### Usability
- **Immediate Public Keys**: GEN_KEY and REGEN_KEY return the generated public key
- **Factory Reset**: Two-phase credential-free reset for lockout recovery
- **Separate PUK Management**: Change PUK independently via SET_PUK (0x7D)

## Common Gotchas

1. **Initialize First** — `CARD_INIT` (0x7F) must be called on a fresh card before anything else
2. **Slot Protection** — `GEN_KEY` fails on occupied slots; use `REGEN_KEY` (0x06)
3. **Hash on host** — Send SHA-256 digests, not raw messages
4. **DER signatures** — Parse DER format to extract r,s for verification
5. **New INS bytes** — If migrating from v1.x, update all instruction bytes (especially REGEN_KEY, CLEAR_KEY, GET_FLAGS)
6. **Reset is credential-free** — Protect physical card access; anyone with the card can factory reset it

### Hardware vs Simulator
- **Real Hardware**: P-256 success rate, ~125ms key generation
- ⚠️ **Simulators**: ~32% success due to environment limitations (expected)
- **Recommendation**: Use real JavaCard hardware for reliable operation

## Status Codes to Watch

- `90 00` — Success
- `69 82` — PIN required, card not initialized, or wrong reset nonce
- `69 85` — Slot occupied (use REGEN_KEY)
- `63 Cx` — Wrong PIN, x tries left
- `69 83` — PIN or PUK blocked
- `6A 82` — No key in slot
- `6A 80` — Invalid flags (reserved bits set)
- `67 00` — Wrong length (invalid APDU format)

## Migration from v1.x

Key changes to update in your code:

```python
# Old v1.x instruction bytes
INS_REGEN_KEY   = 0x08  # → 0x06
INS_CLEAR_KEY   = 0x0A  # → 0x07
INS_GET_FLAGS   = 0x11  # → 0x08
INS_CHANGE_PIN  = 0x06  # → 0x7E (INS_SET_PIN)
INS_UNBLOCK_PIN = 0x09  # → 0x7C (INS_UNBLOCK_CARD)
# INS_SET_FLAGS (0x07) removed entirely

# New: must call CARD_INIT before any key operations on a fresh card
init_cmd = [0x00, 0x7F, len(pin), len(puk), len(pin)+len(puk)] + list(pin) + list(puk)
```

## Next Steps

- Read the full [APPLET_API.md](APPLET_API.md) for complete command reference
- Check [APDU-Protocol-Specification.md](APDU-Protocol-Specification.md) for protocol details
- Check [BUILD_DEPLOYMENT.md](BUILD_DEPLOYMENT.md) for deployment
- Configure key flags for your security requirements
- Set up proper PIN/PUK management and backup

Happy signing!
