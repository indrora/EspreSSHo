package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var pinCmd = &cobra.Command{
	Use:   "pin",
	Short: "Manage the card PIN",
}

func init() {
	pinCmd.AddCommand(pinChangeCmd)
	pinCmd.AddCommand(pinUnblockCmd)
}

var pinChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change the card PIN",
	Long:  "Prompts for the current PIN and the desired new PIN, then updates the card.",
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPIN, err := promptHiddenString("Current PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(oldPIN)

		newPIN, err := promptHiddenString("New PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(newPIN)

		confirm, err := promptHiddenString("Confirm new PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(confirm)

		if string(newPIN) != string(confirm) {
			return fmt.Errorf("PINs do not match")
		}

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.ChangePIN(oldPIN, newPIN); err != nil {
			return fmt.Errorf("change PIN: %w", err)
		}
		fmt.Println("PIN changed.")
		return nil
	},
}

var pinUnblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "Unblock a blocked PIN using the PUK",
	Long:  "Prompts for the PUK and a new PIN, then unblocks and resets the card PIN.",
	RunE: func(cmd *cobra.Command, args []string) error {
		puk, err := promptHiddenString("PUK: ")
		if err != nil {
			return err
		}
		defer zeroSlice(puk)

		newPIN, err := promptHiddenString("New PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(newPIN)

		confirm, err := promptHiddenString("Confirm new PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(confirm)

		if string(newPIN) != string(confirm) {
			return fmt.Errorf("PINs do not match")
		}

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.UnblockPIN(puk, newPIN); err != nil {
			return fmt.Errorf("unblock PIN: %w", err)
		}
		fmt.Println("PIN unblocked and reset.")
		return nil
	},
}

// promptHiddenString reads a PIN from CLI flag if set, otherwise uses SSH_ASKPASS or terminal.
func promptHiddenString(prompt string) ([]byte, error) {
	// Check CLI flag first
	if pinFlag != "" {
		return []byte(pinFlag), nil
	}

	// Fall back to SSH_ASKPASS pattern
	askpass := os.Getenv("SSH_ASKPASS")
	if askpass != "" {
		out, err := exec.Command(askpass, prompt).Output()
		if err != nil {
			return nil, err
		}
		// Trim trailing newline that most askpass helpers append
		return bytes.TrimRight(out, "\n"), nil
	}

	// Fall back to terminal prompt
	fmt.Fprint(os.Stderr, prompt)
	return term.ReadPassword(int(os.Stdin.Fd()))
}

// zeroSlice overwrites a byte slice with zeros.
func zeroSlice(buf []byte) {
	for index := range buf {
		buf[index] = 0
	}
}
