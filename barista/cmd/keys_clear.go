package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var keysClearCmd = &cobra.Command{
	Use:   "clear <slot>",
	Short: "Delete a key from a slot",
	Long: `Delete the keypair from the specified slot.
This permanently removes the key material from the card.
Requires PIN verification.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		pin, err := promptHiddenString(fmt.Sprintf("Enter PIN to clear key in slot %d: ", slot))
		if err != nil {
			return fmt.Errorf("read PIN: %w", err)
		}
		defer zeroSlice(pin)

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.ClearKey(slot, pin); err != nil {
			return fmt.Errorf("clear key: %w", err)
		}

		fmt.Printf("✓ Cleared key from slot %d\n", slot)
		return nil
	},
}
