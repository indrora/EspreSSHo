# EspreSSHo Mokapot - Development Status

## Features in Development

The following security and protection features are implemented in the codebase:

1. **🚧 Key Generation Protection**: `INS_GEN_KEY` implementation that checks slot occupancy
2. **🚧 PIN-Protected Operations**: Write operations with PIN verification logic
3. **🚧 Unified APDU Format**: Consistent [PIN_LEN][PIN][FLAGS] format for destructive operations
4. **🚧 Explicit Flag Model**: Write operations that set flags from APDU data
5. **🚧 Clear Operation Semantics**: `GEN_KEY` vs `REGEN_KEY` with distinct behavior
6. **🚧 Transaction Safety**: Key operations designed to be atomic
7. **🚧 Error Handling**: Error codes defined for failure conditions

## Security Model (Development Implementation)

### Key Generation Protection
- **`INS_GEN_KEY`**: Designed to fail with `SW_KEY_EXISTS (0x6985)` if slot already contains a key
- **`INS_REGEN_KEY`**: Explicitly replaces existing keys (requires PIN)
- **`INS_CLEAR_KEY`**: Securely deletes keys from slots (requires PIN)

### PIN Protection
- All write operations require PIN verification in APDU data
- Non-decremental PIN verification (doesn't consume attempts unnecessarily)
- Returns `SW_SECURITY_STATUS_NOT_SATISFIED (0x6982)` for PIN failures

### Flag Management
- Explicit flag setting in all write operations
- No flag inheritance/preservation (explicit model)
- Validation of reserved flag bits

## Implementation Notes

### Key Storage and Lifecycle
- **Storage**: EC P-256 keypairs stored in EEPROM KeyPair[] array
- **Flags**: Per-slot flags stored in parallel byte[] array
- **Lifecycle**: Keys persist until explicitly cleared or overwritten via REGEN_KEY
- **Transaction Safety**: Key generation and flag setting designed to be atomic

### Protection Logic
- **Slot Validation**: `handleGenKey()` checks slot occupancy before proceeding
- **Clear Errors**: `SW_KEY_EXISTS` provides actionable feedback to users
- **Defensive Programming**: Exception handling treats uninitialized keys safely

### PIN Protection
- **Unified Format**: All destructive operations use [PIN_LEN][PIN][FLAGS] APDU format
- **Validation**: PIN length validation (1-8 bytes) with proper bounds checking
- **Security**: PIN verification required before any key modifications
- **Error Handling**: Clear error responses for PIN failures

### Flag Management
- **Explicit Model**: All write operations require flags in APDU data
- **Validation**: Reserved flag bits are validated and rejected
- **No Inheritance**: Flags are set explicitly, no preservation from previous state

### Testing Status
- **Development Testing**: Test suite exists but relies on simulator
- **Known Issues**: Some tests fail due to simulator limitations, not code issues
- **Real Card Testing**: Needs testing on actual JavaCard hardware

## Available Instructions (Current Implementation)

| INS | Description | APDU Format | Security | Status |
|---|---|---|---|---|
| `0x01` | **INS_GEN_KEY** | [PIN_LEN][PIN][FLAGS] | PIN Required | 🚧 Implemented |
| `0x02` | **INS_GET_PUBKEY** | P1=slot | Public Read | 🚧 Implemented |
| `0x03` | **INS_SIGN** | 32-byte digest | Per-key flags | 🚧 Implemented |
| `0x04` | **INS_LIST_KEYS** | None | Public Read | 🚧 Implemented |
| `0x05` | **INS_VERIFY_PIN** | PIN bytes | PIN Change | 🚧 Implemented |
| `0x06` | **INS_CHANGE_PIN** | Old+New PIN | PIN Required | 🚧 Implemented |
| `0x07` | **INS_SET_FLAGS** | P1=slot, P2=flags | Deprecated | ⚠️ Legacy (use explicit flags in gen/regen) |
| `0x08` | **INS_REGEN_KEY** | [PIN_LEN][PIN][FLAGS] | PIN Required | 🚧 Implemented |
| `0x09` | **INS_UNBLOCK_PIN** | PUK+New PIN | PUK Required | 🚧 Implemented |
| `0x0A` | **INS_CLEAR_KEY** | [PIN_LEN][PIN][FLAGS] | PIN Required | 🚧 Implemented |

## Build Instructions

The build system uses **Apache Ant** with the `ant-javacard` plugin:

### Prerequisites
```bash
# Set JavaCard SDK path (if not using JCKIT_HOME):
export JCKIT_HOME=/path/to/javacard-sdk-3.0.5

# Or pass as property:
ant -Djckit=/path/to/javacard-sdk-3.0.5 build
```

### Building
```bash
# Download dependencies and build CAP file:
ant fetch resolve build

# Output: build/mokapot.cap
```

### Installation  
```bash
# Install to card using GlobalPlatformPro:
gp --install build/mokapot.cap

# Verify installation:
gp --list
```

### Current AID
```
Package AID: CA FE 4D 6F 6B 61 (6 bytes, "CafeMok[a]")
Applet AID:  CA FE 4D 6F 6B 61 00 01 00 00 00 00 00 00 00 00 (16 bytes)
```

### Testing
```bash  
# Run unit tests:
ant test

# Run focused tests:
ant -Dtest.class=SSHKeyAppletTest test
```

---

## Migration Notes (API Changes)

Applications using the old API need updates for:

1. **GEN_KEY Protection**: Handle `SW_KEY_EXISTS (0x6985)` error
2. **PIN-Protected Format**: All write operations now require PIN in APDU data
3. **Explicit Flags**: Provide desired flags in all write operations