package card

import (
	"fmt"

	"github.com/indrora/EspreSSHo/barista/crypto"
)

// encodePINProtectedAPDU builds the unified [PIN_LEN][PIN][FLAGS] format
// used by GenKey, RegenKey, and ClearKey operations.
func encodePINProtectedAPDU(ins byte, slot byte, pin []byte, flags byte) ([]byte, error) {
	if len(pin) < 1 || len(pin) > 8 {
		return nil, fmt.Errorf("PIN length must be 1-8 bytes, got %d", len(pin))
	}

	pinLen := byte(len(pin))
	dataLen := 1 + len(pin) + 1 // PIN_LEN + PIN + FLAGS

	apdu := make([]byte, 5+dataLen)
	apdu[0] = 0x00           // CLA
	apdu[1] = ins            // INS
	apdu[2] = slot           // P1 = slot (0-3)
	apdu[3] = 0x00           // P2 = reserved
	apdu[4] = byte(dataLen)  // Lc = data length
	apdu[5] = pinLen         // PIN_LEN
	copy(apdu[6:], pin)      // PIN data
	apdu[6+len(pin)] = flags // FLAGS (PIN_LEN + PIN + FLAGS)

	return apdu, nil
}

// GenKey generates a new EC P-256 keypair in the given slot (0–3).
// Requires PIN verification. Fails with ErrKeyExists if slot is occupied.
// Use RegenKey to replace an existing key.
func (card *Card) GenKey(slot byte, pin []byte, flags byte) error {
	apdu, err := encodePINProtectedAPDU(INSGenKey, slot, pin, flags)
	if err != nil {
		return fmt.Errorf("GenKey slot %d: %w", slot, err)
	}

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("GenKey slot %d: %w", slot, err)
	}
	return parseSW(sw)
}

// RegenKey regenerates the keypair in a slot (replaces existing key).
// Requires PIN verification. Sets flags explicitly from the flags parameter.
func (card *Card) RegenKey(slot byte, pin []byte, flags byte) error {
	apdu, err := encodePINProtectedAPDU(INSRegenKey, slot, pin, flags)
	if err != nil {
		return fmt.Errorf("RegenKey slot %d: %w", slot, err)
	}

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("RegenKey slot %d: %w", slot, err)
	}
	return parseSW(sw)
}

// ClearKey deletes a key from the given slot.
// Requires PIN verification. The flags parameter is ignored but required for API consistency.
func (card *Card) ClearKey(slot byte, pin []byte) error {
	apdu, err := encodePINProtectedAPDU(INSClearKey, slot, pin, 0x00)
	if err != nil {
		return fmt.Errorf("ClearKey slot %d: %w", slot, err)
	}

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("ClearKey slot %d: %w", slot, err)
	}
	return parseSW(sw)
}

// GetFlags returns the security flags byte for the given slot.
func (card *Card) GetFlags(slot byte) (byte, error) {
	apdu := []byte{0x00, INSGetFlags, slot, 0x00, 0x00}
	resp, sw, err := card.transmit(apdu)
	if err != nil {
		return 0, fmt.Errorf("GetFlags slot %d: %w", slot, err)
	}
	if err := parseSW(sw); err != nil {
		return 0, fmt.Errorf("GetFlags slot %d: %w", slot, err)
	}
	if len(resp) < 1 {
		return 0, fmt.Errorf("GetFlags slot %d: empty response", slot)
	}
	return resp[0], nil
}

// GetPubKey returns the 65-byte uncompressed EC public key for the given slot.
// The first byte is always 0x04 (uncompressed point indicator).
func (card *Card) GetPubKey(slot byte) ([]byte, error) {
	// Le=0x00 requests the full response (up to 256 bytes; pubkey is 65).
	apdu := []byte{0x00, INSGetPubKey, slot, 0x00, 0x00}
	resp, sw, err := card.transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("GetPubKey slot %d: %w", slot, err)
	}
	if err := parseSW(sw); err != nil {
		return nil, fmt.Errorf("GetPubKey slot %d: %w", slot, err)
	}
	if len(resp) != crypto.ECPointLength {
		return nil, fmt.Errorf("GetPubKey slot %d: unexpected response length %d", slot, len(resp))
	}
	return resp, nil
}

// Sign sends a pre-computed digest to the card for signing with the key in the
// given slot. The card uses signPreComputedHash() (JavaCard 3.0.5) so no
// re-hashing occurs on-card.
//
// digest may be the output of any hash function (SHA-256, SHA-512, SHA3-256,
// SHA3-512, …). For P-256 keys, the ECDSA standard (FIPS 186-4 §6.4) uses the
// leftmost 256 bits of the digest, so longer hashes are safely truncated by the
// card's signPreComputedHash() implementation.
//
// extraFlags may include FlagRequirePIN to force a PIN re-check on the card
// regardless of the slot's stored flags. Pass 0 for normal behaviour.
func (card *Card) Sign(slot byte, digest []byte, extraFlags byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("Sign slot %d: digest is empty", slot)
	}
	if len(digest) > 128 {
		// 128 bytes (1024 bits) is a generous upper bound covering any plausible
		// hash output (SHA-512 = 64B, SHA3-512 = 64B, Blake2b-512 = 64B, …).
		// Anything wider is almost certainly a mistake or misuse.
		return nil, fmt.Errorf("Sign slot %d: digest too long (%d bytes; max 128)", slot, len(digest))
	}

	apdu := make([]byte, 5+len(digest))
	apdu[0] = 0x00
	apdu[1] = INSSign
	apdu[2] = slot
	apdu[3] = extraFlags
	apdu[4] = byte(len(digest))
	copy(apdu[5:], digest)

	resp, sw, err := card.transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("Sign slot %d: %w", slot, err)
	}
	if err := parseSW(sw); err != nil {
		return nil, fmt.Errorf("Sign slot %d: %w", slot, err)
	}
	return resp, nil
}

// ListSlots returns a bitmask of occupied key slots.
// Bit N is set if slot N contains an initialised key.
func (card *Card) ListSlots() (byte, error) {
	apdu := []byte{0x00, INSListKeys, 0x00, 0x00, 0x00}
	resp, sw, err := card.transmit(apdu)
	if err != nil {
		return 0, fmt.Errorf("ListSlots: %w", err)
	}
	if err := parseSW(sw); err != nil {
		return 0, fmt.Errorf("ListSlots: %w", err)
	}
	if len(resp) < 1 {
		return 0, fmt.Errorf("ListSlots: empty response")
	}
	return resp[0], nil
}

// VerifyPIN verifies the card PIN for the current session.
// Returns ErrPINBlocked if the PIN is already blocked, or a "wrong PIN, N tries"
// error on a failed attempt.
func (card *Card) VerifyPIN(pinBytes []byte) error {
	if len(pinBytes) == 0 {
		return fmt.Errorf("VerifyPIN: PIN is empty")
	}
	apdu := make([]byte, 5+len(pinBytes))
	apdu[0] = 0x00
	apdu[1] = INSVerifyPIN
	apdu[2] = 0x00
	apdu[3] = 0x00
	apdu[4] = byte(len(pinBytes))
	copy(apdu[5:], pinBytes)

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("VerifyPIN: %w", err)
	}
	return parseSW(sw)
}

// CardInit performs one-time card initialization, setting PIN and PUK.
// This is the only instruction accepted on an uninitialized card (besides SELECT).
// APDU format: CLA INS P1_PIN_LEN P2_PUK_LEN Lc PIN||PUK
func (card *Card) CardInit(pin, puk []byte) error {
	if len(pin) < 1 || len(pin) > 8 {
		return fmt.Errorf("CardInit: PIN length must be 1-8 bytes, got %d", len(pin))
	}
	if len(puk) < 1 || len(puk) > 8 {
		return fmt.Errorf("CardInit: PUK length must be 1-8 bytes, got %d", len(puk))
	}

	dataLen := len(pin) + len(puk)
	apdu := make([]byte, 5+dataLen)
	apdu[0] = 0x00               // CLA
	apdu[1] = INSCardInit        // INS
	apdu[2] = byte(len(pin))     // P1 = PIN length
	apdu[3] = byte(len(puk))     // P2 = PUK length
	apdu[4] = byte(dataLen)      // Lc = total data length
	copy(apdu[5:], pin)          // PIN bytes
	copy(apdu[5+len(pin):], puk) // PUK bytes

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("CardInit: %w", err)
	}
	return parseSW(sw)
}

// SetPIN changes the card PIN. Replaces the old ChangePIN function.
// APDU format: CLA INS P1_OLD_LEN P2 Lc OLD_PIN||NEW_PIN
// Does not require a prior VerifyPIN - the old PIN is verified inline.
func (card *Card) SetPIN(oldPIN, newPIN []byte) error {
	if len(oldPIN) < 1 || len(oldPIN) > 8 {
		return fmt.Errorf("SetPIN: old PIN length must be 1-8 bytes, got %d", len(oldPIN))
	}
	if len(newPIN) < 1 || len(newPIN) > 8 {
		return fmt.Errorf("SetPIN: new PIN length must be 1-8 bytes, got %d", len(newPIN))
	}

	dataLen := len(oldPIN) + len(newPIN)
	apdu := make([]byte, 5+dataLen)
	apdu[0] = 0x00                     // CLA
	apdu[1] = INSSetPIN                // INS
	apdu[2] = byte(len(oldPIN))        // P1 = old PIN length
	apdu[3] = 0x00                     // P2 = reserved
	apdu[4] = byte(dataLen)            // Lc = total data length
	copy(apdu[5:], oldPIN)             // Old PIN bytes
	copy(apdu[5+len(oldPIN):], newPIN) // New PIN bytes

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("SetPIN: %w", err)
	}
	return parseSW(sw)
}

// SetPUK changes the card PUK.
// APDU format: CLA INS P1_OLD_LEN P2 Lc OLD_PUK||NEW_PUK
func (card *Card) SetPUK(oldPUK, newPUK []byte) error {
	if len(oldPUK) < 1 || len(oldPUK) > 8 {
		return fmt.Errorf("SetPUK: old PUK length must be 1-8 bytes, got %d", len(oldPUK))
	}
	if len(newPUK) < 1 || len(newPUK) > 8 {
		return fmt.Errorf("SetPUK: new PUK length must be 1-8 bytes, got %d", len(newPUK))
	}

	dataLen := len(oldPUK) + len(newPUK)
	apdu := make([]byte, 5+dataLen)
	apdu[0] = 0x00                     // CLA
	apdu[1] = INSSetPUK                // INS
	apdu[2] = byte(len(oldPUK))        // P1 = old PUK length
	apdu[3] = 0x00                     // P2 = reserved
	apdu[4] = byte(dataLen)            // Lc = total data length
	copy(apdu[5:], oldPUK)             // Old PUK bytes
	copy(apdu[5+len(oldPUK):], newPUK) // New PUK bytes

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("SetPUK: %w", err)
	}
	return parseSW(sw)
}

// UnblockCard unblocks a blocked PIN using the PUK and sets a new PIN value.
// Replaces the old UnblockPIN function.
// APDU format: CLA INS P1_PUK_LEN P2 Lc PUK||NEW_PIN
func (card *Card) UnblockCard(puk, newPIN []byte) error {
	if len(puk) < 1 || len(puk) > 8 {
		return fmt.Errorf("UnblockCard: PUK length must be 1-8 bytes, got %d", len(puk))
	}
	if len(newPIN) < 1 || len(newPIN) > 8 {
		return fmt.Errorf("UnblockCard: new PIN length must be 1-8 bytes, got %d", len(newPIN))
	}

	dataLen := len(puk) + len(newPIN)
	apdu := make([]byte, 5+dataLen)
	apdu[0] = 0x00                  // CLA
	apdu[1] = INSUnblockCard        // INS
	apdu[2] = byte(len(puk))        // P1 = PUK length
	apdu[3] = 0x00                  // P2 = reserved
	apdu[4] = byte(dataLen)         // Lc = total data length
	copy(apdu[5:], puk)             // PUK bytes
	copy(apdu[5+len(puk):], newPIN) // New PIN bytes

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("UnblockCard: %w", err)
	}
	return parseSW(sw)
}

// ResetCard performs a two-phase factory reset with user confirmation.
// Phase 1: Get nonce from card
// Phase 2: User must type last 4 hex bytes of nonce to confirm, then complete reset
// Returns the last 4 hex bytes that user needs to type for confirmation.
func (card *Card) ResetCardPhase1() ([]byte, error) {
	apdu := []byte{0x00, INSResetCard, 0x00, 0x00, 0x00} // No data for phase 1
	resp, sw, err := card.transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("ResetCard Phase1: %w", err)
	}
	if err := parseSW(sw); err != nil {
		return nil, fmt.Errorf("ResetCard Phase1: %w", err)
	}
	if len(resp) != 16 {
		return nil, fmt.Errorf("ResetCard Phase1: expected 16-byte nonce, got %d bytes", len(resp))
	}

	// Return the full nonce but caller should show last 4 bytes to user for confirmation
	return resp, nil
}

// ResetCardPhase2 completes the factory reset using the nonce from Phase 1.
// The nonce should be the full 16-byte nonce from Phase 1.
func (card *Card) ResetCardPhase2(nonce []byte) error {
	if len(nonce) != 16 {
		return fmt.Errorf("ResetCard Phase2: nonce must be exactly 16 bytes, got %d", len(nonce))
	}

	apdu := make([]byte, 5+16)
	apdu[0] = 0x00         // CLA
	apdu[1] = INSResetCard // INS
	apdu[2] = 0x00         // P1 = reserved
	apdu[3] = 0x00         // P2 = reserved
	apdu[4] = 0x10         // Lc = 16 bytes
	copy(apdu[5:], nonce)  // 16-byte nonce

	_, sw, err := card.transmit(apdu)
	if err != nil {
		return fmt.Errorf("ResetCard Phase2: %w", err)
	}
	return parseSW(sw)
}
