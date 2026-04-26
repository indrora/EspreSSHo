package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
)

// ecdsaDERSignature represents the ASN.1 structure of a DER-encoded ECDSA signature.
type ecdsaDERSignature struct {
	R, S *big.Int
}

// VerifyFileSignature verifies a DER-encoded ECDSA signature against a file using the provided public key.
func VerifyFileSignature(filename string, derSignature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	// Hash the file
	digest, err := HashFile(filename)
	if err != nil {
		return false, fmt.Errorf("hash file: %w", err)
	}
	
	// Parse DER signature
	var ecdsaSig ecdsaDERSignature
	if _, err := asn1.Unmarshal(derSignature, &ecdsaSig); err != nil {
		return false, fmt.Errorf("parse DER signature: %w", err)
	}
	
	// Verify signature
	valid := ecdsa.Verify(publicKey, digest[:], ecdsaSig.R, ecdsaSig.S)
	return valid, nil
}

// VerifySignature verifies a DER-encoded ECDSA signature against a digest using the provided public key.
func VerifySignature(digest []byte, derSignature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	// Parse DER signature
	var ecdsaSig ecdsaDERSignature
	if _, err := asn1.Unmarshal(derSignature, &ecdsaSig); err != nil {
		return false, fmt.Errorf("parse DER signature: %w", err)
	}
	
	// Verify signature
	valid := ecdsa.Verify(publicKey, digest, ecdsaSig.R, ecdsaSig.S)
	return valid, nil
}

// HashFile reads a file and returns its SHA-256 hash.
func HashFile(filename string) ([32]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return [32]byte{}, fmt.Errorf("read file: %w", err)
	}
	
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result, nil
}