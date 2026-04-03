package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var keysFlagsCmd = &cobra.Command{
	Use:        "flags <slot>",
	Short:      "Set per-key policy flags for a slot (deprecated)",
	Deprecated: "Use flag options with 'gen' or 'regen' commands instead",
	Long: `flags sets the policy flags for a key slot. Each flag may be specified;
unspecified flags default to their zero value (off/0).

This command is deprecated in v2.0. Use the flag options (--require-pin, --timeout, 
--erase-on-lock) with the 'gen' or 'regen' commands instead.

Examples:
  barista keys gen 0 --require-pin --timeout 5
  barista keys regen 1 --require-pin --erase-on-lock`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slot, err := parseSlot(args[0])
		if err != nil {
			return err
		}

		flags := buildFlagsFromCmd(cmd)

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