package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/furrytel/espressoho/barista/card"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage keys stored on the card",
}

func init() {
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysGenCmd)
	keysCmd.AddCommand(keysRegenCmd)
	keysCmd.AddCommand(keysFlagsCmd)

	// Flag options for keysFlagsCmd.
	keysFlagsCmd.Flags().Bool("require-pin", false, "Require PIN before each signing operation")
	keysFlagsCmd.Flags().Uint8("timeout", 0, "PIN re-prompt timeout in minutes (0 = session-scoped)")
	keysFlagsCmd.Flags().Bool("erase-on-lock", false, "Erase key if PIN becomes blocked")
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all populated key slots",
	RunE: func(cmd *cobra.Command, args []string) error {
		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		mask, err := cardConn.ListSlots()
		if err != nil {
			return err
		}

		if mask == 0 {
			fmt.Println("No keys on card.")
			return nil
		}

		for slotIndex := byte(0); slotIndex < 4; slotIndex++ {
			if mask&(1<<slotIndex) == 0 {
				continue
			}
			rawPubKey, err := cardConn.GetPubKey(slotIndex)
			if err != nil {
				fmt.Printf("slot %d: error reading pubkey: %v\n", slotIndex, err)
				continue
			}
			sshKey, err := ecPointToSSHPublicKey(rawPubKey)
			if err != nil {
				fmt.Printf("slot %d: error parsing pubkey: %v\n", slotIndex, err)
				continue
			}
			// Print in authorized_keys format.
			fmt.Printf("%s %s mokapot-slot-%d\n",
				sshKey.Type(),
				base64.StdEncoding.EncodeToString(sshKey.Marshal()),
				slotIndex,
			)
		}
		return nil
	},
}

var keysGenCmd = &cobra.Command{
	Use:   "gen <slot>",
	Short: "Generate a new keypair in a slot (0–3)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.GenKey(slot); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		return printSlotPubKey(cardConn, slot)
	},
}

var keysRegenCmd = &cobra.Command{
	Use:   "regen <slot>",
	Short: "Regenerate (replace) the keypair in a slot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		rawPubKey, err := cardConn.RegenKey(slot)
		if err != nil {
			return fmt.Errorf("regenerate key: %w", err)
		}

		sshKey, err := ecPointToSSHPublicKey(rawPubKey)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s mokapot-slot-%d\n",
			sshKey.Type(),
			base64.StdEncoding.EncodeToString(sshKey.Marshal()),
			slot,
		)
		return nil
	},
}

var keysFlagsCmd = &cobra.Command{
	Use:   "flags <slot>",
	Short: "Set per-key policy flags for a slot",
	Long: `flags sets the policy flags for a key slot. Each flag may be specified;
unspecified flags default to their zero value (off/0).

Examples:
  barista keys flags 0 --require-pin
  barista keys flags 1 --require-pin --timeout 5 --erase-on-lock`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		requirePIN, _ := cmd.Flags().GetBool("require-pin")
		timeout, _    := cmd.Flags().GetUint8("timeout")
		eraseOnLock, _ := cmd.Flags().GetBool("erase-on-lock")

		if timeout > 7 {
			return fmt.Errorf("--timeout must be 0–7 (got %d)", timeout)
		}

		var flags byte
		if requirePIN {
			flags |= card.FlagRequirePIN
		}
		flags |= (timeout << card.FlagTimeoutShift) & card.FlagTimeoutMask
		if eraseOnLock {
			flags |= card.FlagEraseOnLock
		}

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.SetFlags(slot, flags); err != nil {
			return fmt.Errorf("set flags: %w", err)
		}
		fmt.Printf("Flags for slot %d set to 0x%02X.\n", slot, flags)
		return nil
	},
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func parseSlot(s string) (byte, error) {
	slotNum, err := strconv.Atoi(s)
	if err != nil || slotNum < 0 || slotNum > 3 {
		return 0, fmt.Errorf("slot must be 0–3 (got %q)", s)
	}
	return byte(slotNum), nil
}

// printSlotPubKey fetches and prints the public key for a slot in authorized_keys format.
func printSlotPubKey(cardConn *card.Card, slot byte) error {
	rawPubKey, err := cardConn.GetPubKey(slot)
	if err != nil {
		return err
	}
	sshKey, err := ecPointToSSHPublicKey(rawPubKey)
	if err != nil {
		return err
	}
	fmt.Printf("%s %s mokapot-slot-%d\n",
		sshKey.Type(),
		base64.StdEncoding.EncodeToString(sshKey.Marshal()),
		slot,
	)
	return nil
}

// ecPointToSSHPublicKey converts a raw 65-byte uncompressed P-256 point to an ssh.PublicKey.
// This mirrors the same conversion in sshagent/agent.go; cmd/ doesn't import sshagent/ to
// avoid a circular dependency concern and to keep the CLI layer self-contained.
func ecPointToSSHPublicKey(rawPoint []byte) (ssh.PublicKey, error) {
	if len(rawPoint) != 65 || rawPoint[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed EC point (length %d)", len(rawPoint))
	}
	x := new(big.Int).SetBytes(rawPoint[1:33])
	y := new(big.Int).SetBytes(rawPoint[33:65])
	ecKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return ssh.NewPublicKey(ecKey)
}
