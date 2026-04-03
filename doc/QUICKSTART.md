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
**Default PIN**: `1234`  
**Default PUK**: `12345678`  
**API Version**: Current implementation (PIN-protected write operations)

## 4-Step Workflow

### 1. Wake Up the Applet
```
SELECT: 00 A4 04 00 10 CA FE 4D 6F 6B 61 00 01 00 00 00 00 00 00 00 00
```

### 2. List Available Keys
```
LIST KEYS: 00 04 00 00
Response: [bitmask] 90 00  (bit N = slot N has key)
```

### 3. Create a Key (Current format)
```
GENERATE: 00 01 00 00 06 04 31 32 33 34 80
          │  │  │  │  │  │  └─ PIN bytes (1234) ─┘ └─ FLAGS (0x80)
          │  │  │  │  │  └─── PIN length (4)
          │  │  │  │  └────── Data length (6: PIN_LEN + PIN + FLAGS)
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

# Sign the hash (example with 32-byte hash)
SIGN: 00 03 00 00 20 [32 bytes of hash]
Response: [DER signature] 90 00
```

## Get Public Key (if needed separately)
```
GET PUBKEY: 00 02 00 00
Response: 04 [32-byte X] [32-byte Y] 90 00
```

## Python Example

```python
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
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

# Generate key in slot 0 (Current format: PIN + flags required)
pin = b"1234"
flags = 0x80  # FLAG_REQUIRE_PIN
gen_cmd = [0x00, 0x01, 0x00, 0x00, len(pin) + 2] + [len(pin)] + list(pin) + [flags]
pubkey_resp, sw1, sw2 = conn.transmit(gen_cmd)
assert (sw1, sw2) == (0x90, 0x00)

print(f"Generated Public Key: {toHexString(pubkey_resp)}")

# List keys to confirm
list_cmd = [0x00, 0x04, 0x00, 0x00]
resp, sw1, sw2 = conn.transmit(list_cmd)
assert (sw1, sw2) == (0x90, 0x00)
print(f"Key slots populated: 0x{resp[0]:02X}")

# Sign something
message = b"Hello, EspreSSHo!"
hash_digest = hashlib.sha256(message).digest()
sign_cmd = [0x00, 0x03, 0x00, 0x00, 0x20] + list(hash_digest)
sig_resp, sw1, sw2 = conn.transmit(sign_cmd)
assert (sw1, sw2) == (0x90, 0x00)

print(f"Signature: {toHexString(sig_resp)}")
```

## Key Features

### 🔧 Enhanced Security
- **PIN Protection**: All write operations require PIN verification
- **Slot Protection**: GEN_KEY fails if slot occupied (prevents accidental overwrites)
- **Atomic Operations**: Key generation and flag setting are transactional

### 🚀 Improved UX  
- **Immediate Public Keys**: GEN_KEY and REGEN_KEY return generated public key
- **Better Error Reporting**: Clear error codes for different failure modes
- **Unified APDU Format**: Consistent PIN+flags format across operations

### Fixed Issues
- **P-256 Compatibility**: 100% success rate on real JavaCard hardware
- **Domain Parameters**: Uses industry-standard secp256r1 parameters
- **Slot Management**: Proper validation prevents false success scenarios

## Common Operations

### Fill All 4 Slots
```bash
# Generate keys in all slots with default flags
gp --apdu 00A4040008CAFE4D6F6B61000100 \
   --apdu 0001000006043132333480 \
   --apdu 0001010006043132333480 \
   --apdu 0001020006043132333480 \
   --apdu 0001030006043132333480
```

### Replace Existing Key
```bash
# Use REGEN_KEY (0x08) instead of GEN_KEY (0x01) for occupied slots
gp --apdu 00A4040008CAFE4D6F6B61000100 \
   --apdu 0008000006043132333400  # slot 0, no special flags
```

### Clear a Key
```bash
# Current implementation: Clear key and flags (requires PIN)
gp --apdu 00A4040008CAFE4D6F6B61000100 \
   --apdu 000A000006043132333400  # clear slot 0
```

## Common Gotchas

1. **Current Format Required** - All write operations need PIN+flags format
2. **Slot Protection** - GEN_KEY fails on occupied slots (use REGEN_KEY)
3. **Hash on host** - Send SHA-256 digests, not raw messages
4. **DER signatures** - Parse the DER format to extract r,s values for verification
5. **Slot numbers** - Valid slots are 0-3, others return errors
6. **PIN Required** - Write operations fail without proper PIN verification

### Hardware vs Simulator
- **Real Hardware**: P-256 success rate, ~125ms key generation  
- ⚠️ **Simulators**: ~32% success due to environment limitations (expected)
- **Recommendation**: Use real JavaCard hardware for reliable operation

## Status Codes to Watch

- `90 00` - Success 
- `69 82` - PIN verification failed 🔐
- `69 85` - Slot occupied (use REGEN_KEY) ⚠️
- `69 84` - Invalid domain parameters (contact support) ❌
- `63 Cx` - Wrong PIN, x tries left 🔑  
- `69 83` - PIN blocked, need PUK 🔒
- `6A 82` - No key in slot 🔍
- `6A 80` - Invalid flags (reserved bits set) ⚙️
- `67 00` - Wrong length (invalid APDU format) 📏

## Migration from v1.x

If you have existing v1.x code, update:

```python
# Old v1.x
gen_cmd = [0x00, 0x01, 0x00, 0x00]

# Current implementation  
pin = b"1234"
flags = 0x80
gen_cmd = [0x00, 0x01, 0x00, 0x00, len(pin) + 2] + [len(pin)] + list(pin) + [flags]
```

## Next Steps

- Read the full [APPLET_API.md](APPLET_API.md) for complete command reference
- Check [BUILD_DEPLOYMENT.md](BUILD_DEPLOYMENT.md) for deployment
- Implement proper ECDSA signature verification in your application
- Configure key flags for your security requirements
- Set up proper PIN/PUK management

Happy signing! 🔐✨