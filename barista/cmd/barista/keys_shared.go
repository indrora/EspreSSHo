package barista

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/indrora/EspreSSHo/barista/card"
	"github.com/indrora/EspreSSHo/barista/crypto"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage keys stored on the card",
}

func init() {
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysGenCmd)
	keysCmd.AddCommand(keysRegenCmd)
	keysCmd.AddCommand(keysClearCmd)

	// Add flags for the list command
	keysListCmd.Flags().BoolP("verbose", "v", false, "Show detailed information including flags")
	keysListCmd.Flags().BoolP("quiet", "q", false, "Show only public keys (authorized_keys format)")

	// Add flag options for key generation and regeneration.
	for _, cmd := range []*cobra.Command{keysGenCmd, keysRegenCmd} {
		cmd.Flags().Bool("require-pin", false, "Require PIN before each signing operation")
		cmd.Flags().Uint8("timeout", 0, "PIN re-prompt timeout in minutes (0 = session-scoped)")
		cmd.Flags().Bool("erase-on-lock", false, "Erase key if PIN becomes blocked")
	}
}

// -------------------------------------------------------------------------
// Shared helper functions
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
	sshKey, err := crypto.RawPointToSSHPublicKey(rawPubKey)
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

// formatSSHPublicKey returns a public key in authorized_keys format.
func formatSSHPublicKey(sshKey ssh.PublicKey, slot byte) string {
	return fmt.Sprintf("%s %s mokapot-slot-%d",
		sshKey.Type(),
		base64.StdEncoding.EncodeToString(sshKey.Marshal()),
		slot,
	)
}

// buildFlagsFromCmd constructs a flags byte from cobra command flags.
func buildFlagsFromCmd(cmd *cobra.Command) byte {
	var flags byte

	requirePIN, err := cmd.Flags().GetBool("require-pin")
	if err != nil {
		// This should not happen with properly defined flags, but log for debugging
		fmt.Fprintf(os.Stderr, "Warning: Failed to read require-pin flag: %v\n", err)
	} else if requirePIN {
		flags |= card.FlagRequirePIN
	}

	timeout, err := cmd.Flags().GetUint8("timeout")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to read timeout flag: %v\n", err)
	} else if timeout > 0 {
		if timeout > crypto.MaxTimeoutMinutes {
			timeout = crypto.MaxTimeoutMinutes // Cap at maximum allowed value
		}
		flags |= (timeout << card.FlagTimeoutShift) & card.FlagTimeoutMask
	}

	eraseOnLock, err := cmd.Flags().GetBool("erase-on-lock")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to read erase-on-lock flag: %v\n", err)
	} else if eraseOnLock {
		flags |= card.FlagEraseOnLock
	}

	return flags
}
