package cmd

import (
	"fmt"
	"os"

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
		oldPIN, err := promptPIN("Current PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(oldPIN)

		newPIN, err := promptPIN("New PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(newPIN)

		confirm, err := promptPIN("Confirm new PIN: ")
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
		puk, err := promptPIN("PUK: ")
		if err != nil {
			return err
		}
		defer zeroSlice(puk)

		newPIN, err := promptPIN("New PIN: ")
		if err != nil {
			return err
		}
		defer zeroSlice(newPIN)

		confirm, err := promptPIN("Confirm new PIN: ")
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

// promptPIN reads a PIN from the terminal without echo.
func promptPIN(prompt string) ([]byte, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pin, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return pin, err
}

// zeroSlice overwrites a byte slice with zeros.
func zeroSlice(buf []byte) {
	for index := range buf {
		buf[index] = 0
	}
}
