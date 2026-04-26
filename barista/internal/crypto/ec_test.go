package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestRawPointToECDSAPublicKey(t *testing.T) {
	// Test valid uncompressed EC point
	validPoint := make([]byte, ECPointLength)
	validPoint[0] = ECUncompressedPrefix
	// Add some test coordinates (not necessarily on curve, just for format test)
	for i := 1; i < ECPointLength; i++ {
		validPoint[i] = byte(i)
	}
	
	_, err := RawPointToECDSAPublicKey(validPoint)
	if err != nil {
		t.Errorf("Valid point should not error, got: %v", err)
	}
	
	// Test invalid length
	shortPoint := make([]byte, 32)
	_, err = RawPointToECDSAPublicKey(shortPoint)
	if err == nil {
		t.Error("Short point should return error")
	}
	
	// Test invalid prefix
	invalidPrefix := make([]byte, ECPointLength)
	invalidPrefix[0] = 0x03 // Compressed prefix, not supported
	_, err = RawPointToECDSAPublicKey(invalidPrefix)
	if err == nil {
		t.Error("Invalid prefix should return error")
	}
}

func TestRawPointToSSHPublicKey(t *testing.T) {
	// Generate a real keypair for testing
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	// Convert to raw point format
	rawPoint := make([]byte, ECPointLength)
	rawPoint[0] = ECUncompressedPrefix
	copy(rawPoint[1:33], privKey.X.Bytes())
	copy(rawPoint[33:65], privKey.Y.Bytes())
	
	sshKey, err := RawPointToSSHPublicKey(rawPoint)
	if err != nil {
		t.Fatalf("Failed to convert to SSH key: %v", err)
	}
	
	if sshKey.Type() != "ecdsa-sha2-nistp256" {
		t.Errorf("Expected ecdsa-sha2-nistp256, got %s", sshKey.Type())
	}
}