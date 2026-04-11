package card

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type KeyInfo struct {
	Slot   uint8
	Flags  uint8
	PubKey ssh.PublicKey
}

func (KeyInfo) String() string {
	return "TODO: Implement"
}

func (key KeyInfo) Fingerprint() string {
	// We don't use the same fingerprint as ssh usually does, since it's a little silly
	sha256sum := sha256.Sum256(key.PubKey.Marshal())
	hash := base32.StdEncoding.EncodeToString(sha256sum[:])
	return hash

}

func (key KeyInfo) FingerprintShort() string {
	sha256sum := sha256.Sum256(key.PubKey.Marshal())
	hash := base32.StdEncoding.EncodeToString(sha256sum[:8])
	return hash
}

func PrintKeyTable(w io.Writer, keys []KeyInfo) {
	fmt.Fprintf(w, "Slot\tFlags\tFingerprint\n")
	for _, key := range keys {
		fmt.Fprintf(w, "%d\t%d\t%s\n", key.Slot, key.Flags, key.FingerprintShort())
	}
}

func (c *Card) ListKeys() ([]KeyInfo, error) {

	keys := make([]KeyInfo, 0)

	slots, err := c.ListSlots()

	if err != nil {
		return nil, err
	}

	for i := range uint8(3) {
		sl := uint8(1) << i
		if (slots & sl) != 0 {
			pubKey, err := c.GetPubKey(uint8(i))
			if err != nil {
				return nil, err
			}

			parsedPubKey, err := ssh.ParsePublicKey(pubKey)
			if err != nil {
				return nil, err
			}
			flags, err := c.GetFlags(i)
			if err != nil {
				return nil, err
			}
			keys = append(keys, KeyInfo{
				Slot:   uint8(i),
				Flags:  flags,
				PubKey: parsedPubKey,
			})
		}
	}
	return keys, nil
}
