package barista

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/indrora/EspreSSHo/barista/card"
	"github.com/indrora/EspreSSHo/barista/crypto"
)

var signCmdRoot = &cobra.Command{
	Use:   "signature <command>",
	Short: "Commands for signing and verifying files with card keys",
	Long:  `Subcommands for signing and verifying files using EC P-256 keys on the card.`,
}

func init() {
	signCmdRoot.AddCommand(sigSignCmd)
	signCmdRoot.AddCommand(keysSigVerify)

	rootCmd.AddCommand(signCmdRoot)
}

const PEMSigType = "ESPRESSHO SIGNATURE"

var sigSignCmd = &cobra.Command{
	Use:   "create <slot> <file>",
	Short: "Sign a file with a card key",
	Long: `Sign a file using the EC P-256 key in the specified slot.
The file is hashed with SHA-256 and the digest is signed on the card.
The signature is output in PEM format.`,
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
				fmt.Fprintf(os.Stderr, "Warning: unable to get flags for slot %d, but --pin was provided; attempting PIN verification anyway\n", slot)
				pin, err := promptHiddenString(fmt.Sprintf("Enter PIN for slot %d: ", slot))
				if err != nil {
					return fmt.Errorf("read PIN: %w", err)
				}
				defer zeroSlice(pin)

				if err := cardConn.VerifyPIN(pin); err != nil {
					// PIN verification failed, but continue anyway
					fmt.Fprintf(os.Stderr, "Warning: PIN verification failed: %v\n", err)
				}
			}
		} else if flags&card.FlagRequirePIN != 0 {
			fmt.Fprintf(os.Stderr, "Slot %d requires PIN verification\n", slot)
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

		pem.Encode(os.Stdout, &pem.Block{
			Headers: map[string]string{
				"File":      filename,
				"Algorithm": "SHA256",
				"Hash":      hex.EncodeToString(digest[:]),
				"Slot":      fmt.Sprintf("%d", slot),
			},
			Type:  PEMSigType,
			Bytes: derSig,
		})

		return nil
	},
}

var keysSigVerify = &cobra.Command{
	Use:   "verify <slot> <file> <signature file>",
	Short: "Verify a file signature using a card key",
	Long: `Verify a file signature using the EC P-256 public key from the specified slot.
The signature should be in PEM format`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		filename := args[1]
		sigFile := args[2]

		f, err := os.Open(sigFile)
		if err != nil {
			return fmt.Errorf("open signature file: %w", err)
		}
		defer f.Close()

		pemBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read signature file: %w", err)
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil || pemBlock.Type != PEMSigType {
			return fmt.Errorf("invalid PEM block in signature file")
		}

		// Decode signature from hex
		derSig := pemBlock.Bytes

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

		if headerSlotStr, ok := pemBlock.Headers["Slot"]; ok {
			headerSlot, err := parseSlot(headerSlotStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: invalid slot header in PEM block: %v\n", err)
			} else if headerSlot != slot {
				fmt.Fprintf(os.Stderr, "Warning: PEM block slot %d does not match expected slot %d\n", headerSlot, slot)
			}
		}

		if hashHex, ok := pemBlock.Headers["Hash"]; ok {
			hashBytes, err := hex.DecodeString(hashHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: invalid hash header in PEM block: %v\n", err)
			} else if !bytes.Equal(digest[:], hashBytes) {
				return fmt.Errorf("PEM block hash does not match computed file hash\n")
			}
		}

		if filenameHeader, ok := pemBlock.Headers["File"]; ok {
			if filenameHeader != filename {
				fmt.Fprintf(os.Stderr, "Warning: PEM block file header %q does not match expected filename %q\n", filenameHeader, filename)
			}
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
