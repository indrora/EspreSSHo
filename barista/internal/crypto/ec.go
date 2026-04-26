package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// RawPointToECDSAPublicKey converts a raw 65-byte uncompressed EC point to *ecdsa.PublicKey.
func RawPointToECDSAPublicKey(rawPoint []byte) (*ecdsa.PublicKey, error) {
	if len(rawPoint) != ECPointLength || rawPoint[0] != ECUncompressedPrefix {
		return nil, fmt.Errorf("invalid uncompressed EC point (expected %d bytes with prefix 0x%02x, got %d bytes)", 
			ECPointLength, ECUncompressedPrefix, len(rawPoint))
	}
	
	x := new(big.Int).SetBytes(rawPoint[1:33])
	y := new(big.Int).SetBytes(rawPoint[33:65])
	
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// RawPointToSSHPublicKey converts a raw 65-byte uncompressed P-256 point to an ssh.PublicKey.
func RawPointToSSHPublicKey(rawPoint []byte) (ssh.PublicKey, error) {
	ecKey, err := RawPointToECDSAPublicKey(rawPoint)
	if err != nil {
		return nil, fmt.Errorf("convert to ECDSA key: %w", err)
	}
	
	sshKey, err := ssh.NewPublicKey(ecKey)
	if err != nil {
		return nil, fmt.Errorf("convert to SSH public key: %w", err)
	}
	
	return sshKey, nil
}