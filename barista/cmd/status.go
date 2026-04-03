package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/furrytel/espressoho/barista/card"
	"github.com/furrytel/espressoho/barista/crypto"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show card and slot status information",
	Long: `status displays information about the connected card, including:
- Reader information
- Slot occupancy
- Key flags for populated slots
- Public key fingerprints`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		// Get slot mask
		mask, err := cardConn.ListSlots()
		if err != nil {
			return fmt.Errorf("list slots: %w", err)
		}

		fmt.Printf("Mokapot Card Status\n")
		fmt.Printf("===================\n")
		fmt.Printf("Reader: %s\n", readerFlag)
		if readerFlag == "" {
			fmt.Printf("Reader: (first available)\n")
		}
		fmt.Printf("Slot mask: 0x%02X\n\n", mask)

		if mask == 0 {
			fmt.Println("No keys found on card.")
			return nil
		}

		for slotIndex := byte(0); slotIndex < 4; slotIndex++ {
			if mask&(1<<slotIndex) == 0 {
				fmt.Printf("Slot %d: empty\n", slotIndex)
				continue
			}

			// Get public key
			rawPubKey, err := cardConn.GetPubKey(slotIndex)
			if err != nil {
				fmt.Printf("Slot %d: error reading pubkey: %v\n", slotIndex, err)
				continue
			}

			sshKey, err := crypto.RawPointToSSHPublicKey(rawPubKey)
			if err != nil {
				fmt.Printf("Slot %d: error parsing pubkey: %v\n", slotIndex, err)
				continue
			}

			// Get flags (temporarily disabled - operation may not exist on card yet)
			// flags, err := cardConn.GetFlags(slotIndex)
			// if err != nil {
			//	fmt.Printf("Slot %d: error reading flags: %v\n", slotIndex, err)
			//	continue
			// }
			flags := byte(0x80) // Assume PIN required for now

			// Display slot info
			fmt.Printf("Slot %d: occupied\n", slotIndex)
			fmt.Printf("  Flags: 0x%02X", flags)
			if flags&card.FlagRequirePIN != 0 {
				timeout := (flags & card.FlagTimeoutMask) >> card.FlagTimeoutShift
				if timeout == 0 {
					fmt.Printf(" (PIN required, session-scoped)")
				} else {
					fmt.Printf(" (PIN required, %d min timeout)", timeout)
				}
			}
			if flags&card.FlagEraseOnLock != 0 {
				fmt.Printf(" (erase on lock)")
			}
			fmt.Printf("\n")
			fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(sshKey))
			fmt.Printf("  Public key: %s\n", formatSSHPublicKey(sshKey, slotIndex))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}