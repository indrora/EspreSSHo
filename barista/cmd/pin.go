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
	pinCmd.AddCommand(pinSetPukCmd)
	pinCmd.AddCommand(cardInitCmd)
	pinCmd.AddCommand(cardResetCmd)
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

		if err := cardConn.SetPIN(oldPIN, newPIN); err != nil {
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

		if err := cardConn.UnblockCard(puk, newPIN); err != nil {
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

var pinSetPukCmd = &cobra.Command{
Use:   "set-puk",
Short: "Change the card PUK",
Long:  "Prompts for the current PUK and the desired new PUK, then updates the card.",
RunE: func(cmd *cobra.Command, args []string) error {
oldPUK, err := promptHiddenString("Current PUK: ")
if err != nil {
return err
}
defer zeroSlice(oldPUK)

newPUK, err := promptHiddenString("New PUK: ")
if err != nil {
return err
}
defer zeroSlice(newPUK)

confirm, err := promptHiddenString("Confirm new PUK: ")
if err != nil {
return err
}
defer zeroSlice(confirm)

if string(newPUK) != string(confirm) {
return fmt.Errorf("PUKs do not match")
}

cardConn, err := connectCard()
if err != nil {
return err
}
defer cardConn.Close()

if err := cardConn.SetPUK(oldPUK, newPUK); err != nil {
return fmt.Errorf("change PUK: %w", err)
}
fmt.Println("PUK changed.")
return nil
},
}

var cardInitCmd = &cobra.Command{
Use:   "init",
Short: "Initialize a new card with PIN and PUK",
Long:  "One-time initialization for a fresh card. Sets the initial PIN and PUK.",
RunE: func(cmd *cobra.Command, args []string) error {
fmt.Println("Initializing card (one-time setup)...")

pin, err := promptHiddenString("Set PIN: ")
if err != nil {
return err
}
defer zeroSlice(pin)

confirmPIN, err := promptHiddenString("Confirm PIN: ")
if err != nil {
return err
}
defer zeroSlice(confirmPIN)

if string(pin) != string(confirmPIN) {
return fmt.Errorf("PINs do not match")
}

puk, err := promptHiddenString("Set PUK: ")
if err != nil {
return err
}
defer zeroSlice(puk)

confirmPUK, err := promptHiddenString("Confirm PUK: ")
if err != nil {
return err
}
defer zeroSlice(confirmPUK)

if string(puk) != string(confirmPUK) {
return fmt.Errorf("PUKs do not match")
}

cardConn, err := connectCard()
if err != nil {
return err
}
defer cardConn.Close()

if err := cardConn.CardInit(pin, puk); err != nil {
return fmt.Errorf("initialize card: %w", err)
}
fmt.Println("Card initialized successfully.")
return nil
},
}

var cardResetCmd = &cobra.Command{
Use:   "reset",
Short: "Factory reset the card (DESTRUCTIVE)",
Long:  "Performs a factory reset, erasing all keys and credentials. Requires confirmation.",
RunE: func(cmd *cobra.Command, args []string) error {
fmt.Println("WARNING: This will PERMANENTLY DELETE all keys and credentials on the card!")
fmt.Print("Type 'yes' to confirm factory reset: ")

var confirmation string
if _, err := fmt.Scanln(&confirmation); err != nil {
return fmt.Errorf("failed to read confirmation: %w", err)
}

if confirmation != "yes" {
fmt.Println("Reset cancelled.")
return nil
}

cardConn, err := connectCard()
if err != nil {
return err
}
defer cardConn.Close()

// Phase 1: Get nonce from card
nonce, err := cardConn.ResetCardPhase1()
if err != nil {
return fmt.Errorf("reset phase 1: %w", err)
}

// Show last 4 bytes to user for final confirmation
lastFour := nonce[12:16]
fmt.Printf("Final confirmation required. Type the last 4 hex bytes: %02x%02x%02x%02x\n", 
lastFour[0], lastFour[1], lastFour[2], lastFour[3])
fmt.Print("Enter confirmation: ")

var hexConfirm string
if _, err := fmt.Scanln(&hexConfirm); err != nil {
return fmt.Errorf("failed to read hex confirmation: %w", err)
}

expectedHex := fmt.Sprintf("%02x%02x%02x%02x", lastFour[0], lastFour[1], lastFour[2], lastFour[3])
if hexConfirm != expectedHex {
fmt.Println("Confirmation failed. Reset cancelled.")
return nil
}

// Phase 2: Complete reset with full nonce
if err := cardConn.ResetCardPhase2(nonce); err != nil {
return fmt.Errorf("reset phase 2: %w", err)
}

fmt.Println("Card has been factory reset. Use 'barista pin init' to reinitialize.")
return nil
},
}
