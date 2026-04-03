package card

import (
	"bytes"
	"testing"
)

func TestEncodePINProtectedAPDU(t *testing.T) {
	tests := []struct {
		name     string
		ins      byte
		slot     byte
		pin      []byte
		flags    byte
		expected []byte
	}{
		{
			name:     "GenKey with PIN 1234 and no flags",
			ins:      INSGenKey,
			slot:     0,
			pin:      []byte("1234"),
			flags:    0x00,
			expected: []byte{0x00, INSGenKey, 0x00, 0x00, 0x06, 0x04, '1', '2', '3', '4', 0x00},
		},
		{
			name:     "ClearKey with PIN 1234",
			ins:      INSClearKey,
			slot:     1,
			pin:      []byte("1234"),
			flags:    0x00,
			expected: []byte{0x00, INSClearKey, 0x01, 0x00, 0x06, 0x04, '1', '2', '3', '4', 0x00},
		},
		{
			name:     "GenKey with PIN 1234 and require-PIN flag",
			ins:      INSGenKey,
			slot:     2,
			pin:      []byte("1234"),
			flags:    FlagRequirePIN,
			expected: []byte{0x00, INSGenKey, 0x02, 0x00, 0x06, 0x04, '1', '2', '3', '4', FlagRequirePIN},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encodePINProtectedAPDU(tt.ins, tt.slot, tt.pin, tt.flags)
			if err != nil {
				t.Fatalf("encodePINProtectedAPDU failed: %v", err)
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("APDU mismatch:\nexpected: %x\nactual:   %x", tt.expected, result)
			}

			// Verify the APDU structure is correct
			if len(result) < 5 {
				t.Fatal("APDU too short")
			}

			dataLen := int(result[4])
			expectedLen := 5 + dataLen
			if len(result) != expectedLen {
				t.Errorf("APDU length mismatch: expected %d, got %d", expectedLen, len(result))
			}

			// Verify flags byte is in the correct position
			flagsPos := 5 + 1 + len(tt.pin) // header + PIN_LEN + PIN
			if result[flagsPos] != tt.flags {
				t.Errorf("flags byte mismatch: expected 0x%02x at position %d, got 0x%02x", 
					tt.flags, flagsPos, result[flagsPos])
			}
		})
	}
}

func TestEncodePINProtectedAPDUErrors(t *testing.T) {
	tests := []struct {
		name string
		pin  []byte
	}{
		{"empty PIN", []byte{}},
		{"PIN too long", make([]byte, 9)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodePINProtectedAPDU(INSGenKey, 0, tt.pin, 0x00)
			if err == nil {
				t.Error("expected error for invalid PIN length")
			}
		})
	}
}