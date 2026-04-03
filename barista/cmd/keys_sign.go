package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/furrytel/espressoho/barista/card"
	"github.com/furrytel/espressoho/barista/crypto"
)

var keysSignCmd = &cobra.Command{
	Use:   "sign <slot> <file>",
	Short: "Sign a file with a card key",
	Long: `Sign a file using the EC P-256 key in the specified slot.
The file is hashed with SHA-256 and the digest is signed on the card.
The signature is output in DER format as hex.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		filename := args[1]

		// Read and hash the file
		digest, err := crypto.HashFile(filename)
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}

		// Connect to card
		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		// Try to get flags to see if PIN is needed, but don't fail if we can't
		flags, err := cardConn.GetFlags(slot)
		if err != nil {
			// If we can't get flags, try to verify PIN anyway if one was provided
			if pinFlag != "" {
				pin, err := promptHiddenString(fmt.Sprintf("Enter PIN for slot %d: ", slot))
				if err != nil {
					return fmt.Errorf("read PIN: %w", err)
				}
				defer zeroSlice(pin)

				if err := cardConn.VerifyPIN(pin); err != nil {
					// PIN verification failed, but continue anyway
					fmt.Printf("Warning: PIN verification failed: %v\n", err)
				}
			}
		} else if flags&card.FlagRequirePIN != 0 {
			pin, err := promptHiddenString(fmt.Sprintf("Enter PIN for slot %d: ", slot))
			if err != nil {
				return fmt.Errorf("read PIN: %w", err)
			}
			defer zeroSlice(pin)

			if err := cardConn.VerifyPIN(pin); err != nil {
				return fmt.Errorf("verify PIN: %w", err)
			}
		}

		// Sign the digest
		derSig, err := cardConn.Sign(slot, digest[:], 0)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}

		fmt.Printf("File: %s\n", filename)
		fmt.Printf("SHA-256: %x\n", digest)
		fmt.Printf("Signature: %x\n", derSig)
		fmt.Printf("Slot: %d\n", slot)

		return nil
	},
}

var keysVerifyCmd = &cobra.Command{
	Use:   "verify <slot> <file> <signature>",
	Short: "Verify a file signature using a card key",
	Long: `Verify a file signature using the EC P-256 public key from the specified slot.
The signature should be in DER format as hex (as output by the sign command).`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		filename := args[1]
		sigHex := args[2]

		// Decode signature from hex
		derSig, err := hex.DecodeString(sigHex)
		if err != nil {
			return fmt.Errorf("decode signature hex: %w", err)
		}

		// Read and hash the file
		digest, err := crypto.HashFile(filename)
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}

		// Get public key from card
		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		rawPubKey, err := cardConn.GetPubKey(slot)
		if err != nil {
			return fmt.Errorf("get public key from slot %d: %w", slot, err)
		}

		// Convert to ECDSA public key
		ecdsaPubKey, err := crypto.RawPointToECDSAPublicKey(rawPubKey)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}

		// Verify signature using crypto package
		valid, err := crypto.VerifySignature(digest[:], derSig, ecdsaPubKey)
		if err != nil {
			return fmt.Errorf("verify signature: %w", err)
		}

		fmt.Printf("File: %s\n", filename)
		fmt.Printf("SHA-256: %x\n", digest)
		fmt.Printf("Signature: %x\n", derSig)
		fmt.Printf("Slot: %d\n", slot)

		if valid {
			fmt.Printf("✓ Signature valid\n")
			return nil
		} else {
			fmt.Printf("✗ Signature invalid\n")
			return fmt.Errorf("signature verification failed")
		}
	},
}
