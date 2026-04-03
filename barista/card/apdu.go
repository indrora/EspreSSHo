// Package card provides a pure interface to the Mokapot JavaCard applet over PC/SC.
// It has no knowledge of the SSH agent protocol, cobra commands, or terminal I/O.
package card

import (
	"errors"
	"fmt"
)

// AppletAID is the 7-byte AID of the Mokapot SSH-key applet.
// Must match the applet AID declared in mokapot/build.gradle.
var AppletAID = []byte{0xF0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}

// APDU instruction bytes (INS field).
const (
	INSGenKey     = byte(0x01) // Generate keypair in slot
	INSGetPubKey  = byte(0x02) // Return uncompressed public key
	INSSign       = byte(0x03) // Sign message, return DER signature
	INSListKeys   = byte(0x04) // Return bitmask of populated slots
	INSVerifyPIN  = byte(0x05) // Verify card PIN
	INSChangePIN  = byte(0x06) // Change card PIN (old || new)
	INSSetFlags   = byte(0x07) // Set per-key flags
	INSRegenKey   = byte(0x08) // Regenerate keypair, return new pubkey
	INSUnblockPIN = byte(0x09) // Unblock PIN with PUK
)

// Per-key flag bits. Stored on-card and also used in P2 of INSSign.
const (
	FlagRequirePIN   = byte(0x80) // Bit 7: require PIN before signing
	FlagTimeoutMask  = byte(0x70) // Bits 6–4: timeout in minutes (0 = session)
	FlagTimeoutShift = byte(4)    // Right-shift to extract timeout value
	FlagEraseOnLock  = byte(0x08) // Bit 3: erase key material when PIN blocks
)

// ErrPINBlocked is returned when the card PIN is blocked and a PUK is required.
var ErrPINBlocked = errors.New("card PIN is blocked — use 'barista pin unblock' to recover")

// parseSW converts a PC/SC status word to a Go error.
// Returns nil for SW 0x9000 (success).
func parseSW(sw uint16) error {
	switch {
	case sw == 0x9000:
		return nil
	case sw == 0x6983:
		return ErrPINBlocked
	case sw&0xFFF0 == 0x63C0:
		return fmt.Errorf("wrong PIN, %d tries remaining", sw&0x000F)
	default:
		return fmt.Errorf("unexpected status word: %04X", sw)
	}
}
