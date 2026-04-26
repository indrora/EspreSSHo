package card

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"

	"github.com/indrora/EspreSSHo/barista/crypto"
	"golang.org/x/crypto/ssh"
)

type KeyInfo struct {
	Slot   uint8
	Flags  uint8
	PubKey ssh.PublicKey
}

func (k KeyInfo) String() string {
	return fmt.Sprintf("<key slot=%d, flags=%x, pubkey=%s>", k.Slot, k.Flags, k.FingerprintShort())
}

var encoder base32.Encoding

func init() {
	encoder = *base32.HexEncoding.WithPadding(base32.NoPadding)
}

func (key KeyInfo) Fingerprint() string {
	// We don't use the same fingerprint as ssh usually does, since it's a little silly
	sha256sum := sha256.Sum256(key.PubKey.Marshal())
	hash := encoder.EncodeToString(sha256sum[:])
	return hash

}

func (key KeyInfo) FingerprintShort() string {
	sha256sum := sha256.Sum256(key.PubKey.Marshal())
	hash := encoder.EncodeToString(sha256sum[:8])
	return hash
}

func PrintKeyTable(w io.Writer, keys []KeyInfo) {
	fmt.Fprintf(w, "Slot\tFlags\tFingerprint\n")
	for _, key := range keys {
		fmt.Fprintf(w, "%d\t%d\t%s\n", key.Slot, key.Flags, key.FingerprintShort())
	}
}

func (c *Card) ListKeys() ([]KeyInfo, error) {

	mask, err := c.ListSlots()
	if err != nil {
		return nil, err
	}

	if mask == 0 {
		return nil, nil
	}

	keys := make([]KeyInfo, 0)

	for slotIndex := byte(0); slotIndex < 4; slotIndex++ {
		if mask&(1<<slotIndex) == 0 {
			continue
		}
		rawPubKey, err := c.GetPubKey(slotIndex)
		if err != nil {
			fmt.Printf("slot %d: error reading pubkey: %v\n", slotIndex, err)
			continue
		}
		sshKey, err := crypto.RawPointToSSHPublicKey(rawPubKey)
		if err != nil {
			return nil, err
		}

		flags, err := c.GetFlags(slotIndex)

		keys = append(keys, KeyInfo{
			Slot:   slotIndex,
			Flags:  flags,
			PubKey: sshKey,
		})

	}

	return keys, nil
}
