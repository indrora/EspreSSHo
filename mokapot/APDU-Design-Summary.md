# APDU Format Implementation Summary

## Overview

This document summarizes the unified APDU format for all PIN-protected write operations in the EspreSSHo JavaCard applet. This format provides consistency and security in the development implementation.

## Unified APDU Format

All PIN-protected write operations now use identical APDU structure:

```
Field    | Size    | Description
---------|---------|-------------
CLA      | 1 byte  | 0x00 (standard ISO command class)
INS      | 1 byte  | Operation instruction (0x01, 0x08, 0x0A)  
P1       | 1 byte  | Key slot number (0-3)
P2       | 1 byte  | Reserved, must be 0x00
Lc       | 1 byte  | Length of data field
PIN_LEN  | 1 byte  | PIN length (1-8 bytes)
PIN      | N bytes | PIN data (variable length 1-8)
FLAGS    | 1 byte  | Security flags to set
```

## Instructions Using This Format

1. **INS_GEN_KEY (0x01)** - Generate new keypair
2. **INS_REGEN_KEY (0x08)** - Regenerate existing keypair  
3. **INS_CLEAR_KEY (0x0A)** - Delete key from slot

## Size Constraints

- **Minimum APDU**: 8 bytes (CLA+INS+P1+P2+Lc+PIN_LEN+PIN(1)+FLAGS)
- **Maximum APDU**: 15 bytes (CLA+INS+P1+P2+Lc+PIN_LEN+PIN(8)+FLAGS)
- **PIN Length**: 1-8 bytes (enforced by PIN_LEN validation)
- **Within JavaCard APDU limits**

## Example APDU (Development Implementation)

Generate key in slot 0 with PIN "1234" and flags 0x80:
```
00 01 00 00 06 04 31 32 33 34 80
^^ ^^ ^^ ^^ ^^ ^^ ^^^^^^^^^^^ ^^
|  |  |  |  |  |  |           FLAGS (0x80)
|  |  |  |  |  |  PIN data ("1234")  
|  |  |  |  |  PIN_LEN (4)
|  |  |  |  Lc = 4 + 1 + 1 = 6
|  |  |  P2 (reserved)
|  |  P1 (slot 0)
|  INS_GEN_KEY
CLA
```

This example shows the intended APDU format structure.

## Implementation Constants

### Instructions
```java
public static final byte INS_GEN_KEY = (byte) 0x01;      // Implemented
public static final byte INS_REGEN_KEY = (byte) 0x08;    // Implemented  
public static final byte INS_CLEAR_KEY = (byte) 0x0A;    // Implemented
```

### Status Words
```java
public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;
public static final short SW_KEY_EXISTS = (short) 0x6985;
public static final short SW_KEY_NOT_FOUND = (short) 0x6A82;
public static final short SW_SUCCESS = (short) 0x9000;
```

## Error Responses

- **SW_SECURITY_STATUS_NOT_SATISFIED (0x6982)**: PIN verification failed
- **SW_KEY_EXISTS (0x6985)**: Key slot occupied (GEN_KEY only)
- **SW_KEY_NOT_FOUND (0x6A82)**: Key slot empty (CLEAR_KEY/REGEN_KEY only)
- **SW_WRONG_LENGTH (0x6700)**: Invalid APDU or PIN length
- **SW_SUCCESS (0x9000)**: Operation completed successfully

## Common Parsing Pattern (Development Implementation)

The following pattern is implemented in the current SSHKeyApplet:

```java
// Extract components from APDU
byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
short dataLen = apdu.setIncomingAndReceive();
byte[] buffer = apdu.getBuffer();
byte pinLen = buffer[ISO7816.OFFSET_CDATA];

// Validate PIN length
if (pinLen < 1 || pinLen > 8) {
    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
}

// Validate total data length
if (dataLen != (short)(1 + pinLen + 1)) {
    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
}

// Extract PIN (copy for safety)
byte[] pin = new byte[pinLen];
Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pin, (short)0, pinLen);

// Extract flags
byte flags = buffer[ISO7816.OFFSET_CDATA + 1 + pinLen];

// Verify PIN (implemented)
if (!pin.check(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pinLen)) {
    ISOException.throwIt(APDUConstants.SW_SECURITY_STATUS_NOT_SATISFIED);
}
```

## API Changes (Development Implementation)

- **INS_GEN_KEY**: Now requires PIN verification and fails if slot occupied
- **INS_REGEN_KEY**: Now requires PIN verification for key replacement  
- **INS_CLEAR_KEY**: Implemented for secure key deletion

## Security Features

- PIN verification required for all key modifications
- Variable PIN length support (1-8 bytes)
- Security flags embedded in each operation
- Consistent error handling across all operations
- Safe PIN extraction with bounds checking
- Slot occupancy protection

## Implementation Status

This design has been implemented in the codebase:

1. **PIN verification mechanism** - Implemented in SSHKeyApplet.java
2. **Individual instruction handlers** - All handlers implemented  
3. **Security flag processing** - Flag validation implemented
4. **Testing** - Test suite exists (simulator-based, some limitations)

The unified format provides security for all key operations but requires testing on real JavaCard hardware.