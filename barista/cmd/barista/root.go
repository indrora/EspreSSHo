// Package cmd contains the cobra command tree for the barista CLI.
package barista

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/indrora/EspreSSHo/barista/internal/card"
)

// readerFlag is the value of the persistent --reader flag, shared by all subcommands.
var readerFlag string

// pinFlag and pukFlag are values of the persistent --pin and --puk flags for CLI automation.
var pinFlag string
var pukFlag string

// rootCmd is the top-level cobra command.
var rootCmd = &cobra.Command{
	Use:   "barista",
	Short: "Key and PIN management for Mokapot JavaCard",
	Long: `barista manages keys and PINs on a Mokapot JavaCard applet over PC/SC.
Use crema for SSH agent functionality.`,
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(
		&readerFlag,
		"reader", "",
		"PC/SC reader name or substring (default: first available reader)",
	)
	rootCmd.PersistentFlags().StringVar(
		&pinFlag,
		"pin", "",
		"PIN for CLI automation (default: prompt user)",
	)
	rootCmd.PersistentFlags().StringVar(
		&pukFlag,
		"puk", "",
		"PUK for CLI automation (default: prompt user)",
	)

	// readers subcommand — handy for discovering reader names.
	rootCmd.AddCommand(&cobra.Command{
		Use:   "readers",
		Short: "List available PC/SC readers",
		RunE: func(cmd *cobra.Command, args []string) error {
			readers, err := card.ListReaders()
			if err != nil {
				return err
			}
			if len(readers) == 0 {
				fmt.Println("No PC/SC readers found.")
				return nil
			}
			for _, name := range readers {
				fmt.Println(name)
			}
			return nil
		},
	})

	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(pinCmd)
}

// connectCard is a shared helper used by subcommands that need a card connection.
func connectCard() (*card.Card, error) {
	return card.Connect(readerFlag)
}
