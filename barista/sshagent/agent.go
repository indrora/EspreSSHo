// Package sshagent implements golang.org/x/crypto/ssh/agent.Agent backed by a
// Mokapot JavaCard. It owns the PIN prompting logic because PIN decisions are an
// agent concern, not a card-interface concern.
package sshagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/furrytel/espressoho/barista/card"
)

// keySlot caches the SSH public key and PIN state for one card slot.
type keySlot struct {
	publicKey   ssh.PublicKey
	flags       byte
	pinVerified bool
	lastPINTime time.Time
}

// CardAgent implements agent.Agent using a Mokapot JavaCard.
//
// Use New to create one; the card must already be connected and have its applet
// selected. Call agent.ServeAgent(cardAgent, conn) to handle an SSH agent session.
type CardAgent struct {
	cardConn *card.Card
	slots    [4]keySlot
}

// New creates a CardAgent and loads public keys from all populated card slots.
func New(cardConn *card.Card) (*CardAgent, error) {
	agentInstance := &CardAgent{cardConn: cardConn}
	if err := agentInstance.refreshSlots(); err != nil {
		return nil, fmt.Errorf("load card keys: %w", err)
	}
	return agentInstance, nil
}

// refreshSlots re-reads the slot bitmask and public keys from the card.
// Called at startup and whenever a PIN-block event might have erased keys.
func (agentInstance *CardAgent) refreshSlots() error {
	mask, err := agentInstance.cardConn.ListSlots()
	if err != nil {
		return err
	}
	for slotIndex := byte(0); slotIndex < 4; slotIndex++ {
		if mask&(1<<slotIndex) == 0 {
			agentInstance.slots[slotIndex] = keySlot{} // slot is empty or was erased
			continue
		}
		rawPubKey, err := agentInstance.cardConn.GetPubKey(slotIndex)
		if err != nil {
			return fmt.Errorf("get pubkey slot %d: %w", slotIndex, err)
		}
		sshKey, err := ecPointToSSHKey(rawPubKey)
		if err != nil {
			return fmt.Errorf("parse pubkey slot %d: %w", slotIndex, err)
		}
		// Preserve PIN state across a refresh so a freshly-verified session isn't lost.
		agentInstance.slots[slotIndex].publicKey = sshKey
	}
	return nil
}

// -------------------------------------------------------------------------
// agent.Agent interface
// -------------------------------------------------------------------------

// List returns all currently populated key slots as agent.Key entries.
func (agentInstance *CardAgent) List() ([]*agent.Key, error) {
	var keys []*agent.Key
	for slotIndex, slot := range agentInstance.slots {
		if slot.publicKey == nil {
			continue
		}
		keys = append(keys, &agent.Key{
			Format:  slot.publicKey.Type(),
			Blob:    slot.publicKey.Marshal(),
			Comment: fmt.Sprintf("mokapot-slot-%d", slotIndex),
		})
	}
	return keys, nil
}

// Sign signs data using the key matching the provided public key.
// If the slot requires a PIN, the user is prompted via SSH_ASKPASS or the terminal.
func (agentInstance *CardAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	slotIndex, found := agentInstance.findSlot(key)
	if !found {
		return nil, fmt.Errorf("key not found on card")
	}

	if agentInstance.needsPIN(slotIndex) {
		if err := agentInstance.promptAndVerifyPIN(slotIndex); err != nil {
			return nil, err
		}
	}

	// Hash on the host side; the card uses signPreComputedHash() and does not re-hash.
	// SHA-256 is correct for ecdsa-sha2-nistp256 per RFC 5656 §6.2.1.
	digest := sha256.Sum256(data)
	derSig, err := agentInstance.cardConn.Sign(slotIndex, digest[:], 0)
	if err != nil {
		// If the PIN just got blocked on the card, refresh our key cache.
		if errors.Is(err, card.ErrPINBlocked) {
			agentInstance.refreshSlots() //nolint:errcheck — best-effort refresh
		}
		return nil, fmt.Errorf("sign slot %d: %w", slotIndex, err)
	}

	sigBlob, err := derToSSHBlob(derSig)
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}

	return &ssh.Signature{
		Format: "ecdsa-sha2-nistp256",
		Blob:   sigBlob,
	}, nil
}

// The following operations are not supported — Mokapot manages its own keys.

func (agentInstance *CardAgent) Add(agent.AddedKey) error      { return errors.New("not supported") }
func (agentInstance *CardAgent) Remove(ssh.PublicKey) error     { return errors.New("not supported") }
func (agentInstance *CardAgent) RemoveAll() error               { return errors.New("not supported") }
func (agentInstance *CardAgent) Lock([]byte) error              { return errors.New("not supported") }
func (agentInstance *CardAgent) Unlock([]byte) error            { return errors.New("not supported") }
func (agentInstance *CardAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("not supported") }

// -------------------------------------------------------------------------
// PIN helpers
// -------------------------------------------------------------------------

// needsPIN returns true if the given slot requires a PIN prompt right now.
//
// Logic (CLAUDE.md §PIN Handling):
//  1. If FLAG_REQUIRE_PIN is not set → no PIN needed.
//  2. If not yet verified this session → need PIN.
//  3. If timeout bits == 0 → session-scoped, already verified → no PIN.
//  4. If time since last verification > timeout → need PIN.
func (agentInstance *CardAgent) needsPIN(slotIndex byte) bool {
	slot := agentInstance.slots[slotIndex]
	if slot.flags&card.FlagRequirePIN == 0 {
		return false
	}
	if !slot.pinVerified {
		return true
	}
	timeoutMinutes := (slot.flags & card.FlagTimeoutMask) >> card.FlagTimeoutShift
	if timeoutMinutes == 0 {
		// Session-scoped: verified once this session is enough.
		return false
	}
	return time.Since(slot.lastPINTime) > time.Duration(timeoutMinutes)*time.Minute
}

// promptAndVerifyPIN prompts for the PIN, sends it to the card, and records the result.
func (agentInstance *CardAgent) promptAndVerifyPIN(slotIndex byte) error {
	pinBytes, err := readPIN(fmt.Sprintf("Enter PIN for card key (slot %d): ", slotIndex))
	if err != nil {
		return fmt.Errorf("read PIN: %w", err)
	}
	defer zeroBytes(pinBytes)

	if err := agentInstance.cardConn.VerifyPIN(pinBytes); err != nil {
		return err
	}

	agentInstance.slots[slotIndex].pinVerified = true
	agentInstance.slots[slotIndex].lastPINTime = time.Now()
	return nil
}

// readPIN prompts the user for a PIN. It uses SSH_ASKPASS if set (for GUI/headless
// environments), otherwise reads directly from the controlling terminal.
func readPIN(prompt string) ([]byte, error) {
	if askpass := os.Getenv("SSH_ASKPASS"); askpass != "" {
		out, err := exec.Command(askpass, prompt).Output()
		if err != nil {
			return nil, fmt.Errorf("SSH_ASKPASS failed: %w", err)
		}
		// Trim trailing newline that most askpass helpers append.
		if len(out) > 0 && out[len(out)-1] == '\n' {
			out = out[:len(out)-1]
		}
		return out, nil
	}

	// Fall back to reading from the terminal directly.
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pinBytes, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty) // move to next line after hidden input
	return pinBytes, err
}

// zeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func zeroBytes(buf []byte) {
	for index := range buf {
		buf[index] = 0
	}
}

// -------------------------------------------------------------------------
// Cryptographic helpers
// -------------------------------------------------------------------------

// findSlot returns the slot index whose public key matches key, and whether one was found.
func (agentInstance *CardAgent) findSlot(key ssh.PublicKey) (byte, bool) {
	target := key.Marshal()
	for slotIndex, slot := range agentInstance.slots {
		if slot.publicKey != nil && string(slot.publicKey.Marshal()) == string(target) {
			return byte(slotIndex), true
		}
	}
	return 0, false
}

// ecPointToSSHKey converts a raw 65-byte uncompressed EC point (04 || X || Y)
// into an ssh.PublicKey for the ecdsa-sha2-nistp256 algorithm.
func ecPointToSSHKey(rawPoint []byte) (ssh.PublicKey, error) {
	if len(rawPoint) != 65 || rawPoint[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed EC point (length %d)", len(rawPoint))
	}
	x := new(big.Int).SetBytes(rawPoint[1:33])
	y := new(big.Int).SetBytes(rawPoint[33:65])

	// ssh.NewPublicKey accepts *ecdsa.PublicKey directly.
	ecKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return ssh.NewPublicKey(ecKey)
}

// ecdsaDERSignature is the ASN.1 structure returned by the card.
type ecdsaDERSignature struct {
	R, S *big.Int
}

// derToSSHBlob converts a DER-encoded ECDSA signature to the SSH wire format
// for ecdsa-sha2-nistp256: ssh.Marshal({R, S}).
func derToSSHBlob(derSig []byte) ([]byte, error) {
	var sig ecdsaDERSignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal DER signature: %w", err)
	}
	// golang.org/x/crypto/ssh encodes the blob as: uint32-prefixed R || uint32-prefixed S
	// using its own mpint encoding, which ssh.Marshal handles correctly.
	return ssh.Marshal(sig), nil
}
