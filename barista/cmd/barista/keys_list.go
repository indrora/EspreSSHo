package barista

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/indrora/EspreSSHo/barista/card"
	"github.com/indrora/EspreSSHo/barista/crypto"
)

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all populated key slots",
	Long: `List all keys stored on the card with their flags and fingerprints.
Use --verbose for detailed information or --quiet for just the public keys.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to read verbose flag: %v\n", err)
		}
		quiet, err := cmd.Flags().GetBool("quiet")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to read quiet flag: %v\n", err)
		}

		mask, err := cardConn.ListSlots()
		if err != nil {
			return err
		}

		if mask == 0 {
			if !quiet {
				fmt.Println("No keys on card.")
			}
			return nil
		}

		ks, err := cardConn.ListKeys()

		for _, k := range ks {
			_, err := fmt.Print(k)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to print key info: %v\n", err)
			}
			fmt.Println()
		}

		fmt.Printf("Found %d keys!", len(ks))

		for slotIndex := byte(0); slotIndex < 4; slotIndex++ {
			if mask&(1<<slotIndex) == 0 {
				continue
			}
			rawPubKey, err := cardConn.GetPubKey(slotIndex)
			if err != nil {
				fmt.Printf("slot %d: error reading pubkey: %v\n", slotIndex, err)
				continue
			}
			sshKey, err := crypto.RawPointToSSHPublicKey(rawPubKey)
			if err != nil {
				fmt.Printf("slot %d: error parsing pubkey: %v\n", slotIndex, err)
				continue
			}

			if quiet {
				// Just print the public key in authorized_keys format.
				fmt.Println(formatSSHPublicKey(sshKey, slotIndex))
			} else if verbose {
				// Print detailed information including flags.
				flags, err := cardConn.GetFlags(slotIndex)
				if err != nil {
					fmt.Printf("slot %d: error reading flags: %v\n", slotIndex, err)
					continue
				}

				fmt.Printf("Slot %d:\n", slotIndex)
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
			} else {
				// Default: show flags, fingerprint, and public key
				flags, err := cardConn.GetFlags(slotIndex)
				if err != nil {
					fmt.Printf("slot %d: error reading flags: %v\n", slotIndex, err)
					continue
				}

				fmt.Printf("Slot %d: flags=0x%02X", slotIndex, flags)
				if flags&card.FlagRequirePIN != 0 {
					timeout := (flags & card.FlagTimeoutMask) >> card.FlagTimeoutShift
					if timeout == 0 {
						fmt.Printf(" (PIN/session)")
					} else {
						fmt.Printf(" (PIN/%dmin)", timeout)
					}
				}
				if flags&card.FlagEraseOnLock != 0 {
					fmt.Printf(" (erase-on-lock)")
				}
				fmt.Printf("\n")
				fmt.Printf("  %s  # %s\n",
					formatSSHPublicKey(sshKey, slotIndex),
					ssh.FingerprintSHA256(sshKey),
				)
			}
		}
		return nil
	},
}
