package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var keysGenCmd = &cobra.Command{
	Use:   "gen <slot>",
	Short: "Generate a new keypair in a slot (0–3)",
	Long: `Generate a new EC P-256 keypair in the specified slot.
Requires PIN verification and will fail if the slot is already occupied.
Use 'regen' to replace an existing key.

Flags can be set using the --require-pin, --timeout, and --erase-on-lock options.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		pin, err := promptHiddenString(fmt.Sprintf("Enter PIN to generate key in slot %d: ", slot))
		if err != nil {
			return fmt.Errorf("read PIN: %w", err)
		}
		defer zeroSlice(pin)

		flags := buildFlagsFromCmd(cmd)

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.GenKey(slot, pin, flags); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		fmt.Printf("✓ Generated key in slot %d with flags 0x%02X\n", slot, flags)
		return printSlotPubKey(cardConn, slot)
	},
}

var keysRegenCmd = &cobra.Command{
	Use:   "regen <slot>",
	Short: "Regenerate (replace) the keypair in a slot",
	Long: `Regenerate the EC P-256 keypair in the specified slot.
This replaces any existing key and sets flags explicitly from the command options.
Requires PIN verification.

Flags can be set using the --require-pin, --timeout, and --erase-on-lock options.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		pin, err := promptHiddenString(fmt.Sprintf("Enter PIN to regenerate key in slot %d: ", slot))
		if err != nil {
			return fmt.Errorf("read PIN: %w", err)
		}
		defer zeroSlice(pin)

		flags := buildFlagsFromCmd(cmd)

		cardConn, err := connectCard()
		if err != nil {
			return err
		}
		defer cardConn.Close()

		if err := cardConn.RegenKey(slot, pin, flags); err != nil {
			return fmt.Errorf("regenerate key: %w", err)
		}

		fmt.Printf("✓ Regenerated key in slot %d with flags 0x%02X\n", slot, flags)
		return printSlotPubKey(cardConn, slot)
	},
}
