// Package card provides a pure interface to the Mokapot JavaCard applet over PC/SC.
// It has no knowledge of the SSH agent protocol, cobra commands, or terminal I/O.
package card

import (
	"errors"
	"fmt"
)

// AppletAID is the AID of the Mokapot SSH-key applet.
// Must match the applet AID declared in mokapot/build.xml.
// Using the shorter RID for selection as some cards prefer this.
var AppletAID = []byte{0xCA, 0xFE, 0x4D, 0x6F, 0x6B, 0x61}

// APDU instruction bytes (INS field).
//
// PIN-PROTECTED WRITE OPERATIONS use unified APDU format:
// CLA INS P1  P2  Lc  Data
// 00  XX  slot 00  N   [PIN_LEN][PIN][FLAGS]
//
// Where PIN-protected operations are: INSGenKey, INSRegenKey, INSClearKey
const (
	INSGenKey     = byte(0x01) // Generate keypair in slot (PIN-protected)
	INSGetPubKey  = byte(0x02) // Return uncompressed public key
	INSGetFlags   = byte(0x11) // Return flags byte for a slot  
	INSSign       = byte(0x03) // Sign message, return DER signature
	INSListKeys   = byte(0x04) // Return bitmask of populated slots
	INSVerifyPIN  = byte(0x05) // Verify card PIN
	INSChangePIN  = byte(0x06) // Change card PIN (old || new)
	INSSetFlags   = byte(0x07) // Set per-key flags (deprecated in v2.0)
	INSRegenKey   = byte(0x08) // Regenerate keypair (PIN-protected)
	INSUnblockPIN = byte(0x09) // Unblock PIN with PUK
	INSClearKey   = byte(0x0A) // Clear key from slot (PIN-protected)
)

// Per-key flag bits. Stored on-card and also used in P2 of INSSign.
const (
	FlagRequirePIN   = byte(0x80) // Bit 7: require PIN before signing
	FlagTimeoutMask  = byte(0x70) // Bits 6–4: timeout in minutes (0 = session)
	FlagTimeoutShift = byte(4)    // Right-shift to extract timeout value
	FlagEraseOnLock  = byte(0x08) // Bit 3: erase key material when PIN blocks
)

// Error variables for common card conditions.
var (
	ErrPINBlocked          = errors.New("card PIN is blocked — use 'barista pin unblock' to recover")
	ErrSecurityNotSatisfied = errors.New("PIN verification failed")
	ErrKeyExists           = errors.New("key slot already occupied — use regen-key to replace")
	ErrKeyNotFound         = errors.New("key slot is empty")
	ErrWrongLength         = errors.New("invalid APDU or PIN length")
)

// Status word constants (matches APDUConstants.java).
const (
	SWSuccess                      = uint16(0x9000) // Command completed successfully
	SWPINBlocked                   = uint16(0x6983) // PIN blocked; PUK required
	SWWrongPINBase                 = uint16(0x63C0) // Wrong PIN; low nibble = tries remaining
	SWKeyNotFound                  = uint16(0x6A82) // Key slot is empty
	SWSecurityStatusNotSatisfied   = uint16(0x6982) // PIN verification failed
	SWKeyExists                    = uint16(0x6985) // Key slot already occupied
	SWWrongLength                  = uint16(0x6700) // Invalid APDU or PIN length
)

// parseSW converts a PC/SC status word to a Go error.
// Returns nil for SW 0x9000 (success).
func parseSW(sw uint16) error {
	switch {
	case sw == SWSuccess:
		return nil
	case sw == SWPINBlocked:
		return ErrPINBlocked
	case sw == SWSecurityStatusNotSatisfied:
		return ErrSecurityNotSatisfied
	case sw == SWKeyExists:
		return ErrKeyExists
	case sw == SWKeyNotFound:
		return ErrKeyNotFound
	case sw == SWWrongLength:
		return ErrWrongLength
	case sw&0xFFF0 == SWWrongPINBase:
		return fmt.Errorf("wrong PIN, %d tries remaining", sw&0x000F)
	default:
		return fmt.Errorf("unexpected status word: %04X", sw)
	}
}
