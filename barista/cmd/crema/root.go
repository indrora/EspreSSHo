// Package crema contains the cobra command tree for the crema CLI.
package crema

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/indrora/EspreSSHo/barista/internal/card"
)

// readerFlag is the value of the persistent --reader flag, shared by all subcommands.
var readerFlag string

// rootCmd is the top-level cobra command.
var rootCmd = &cobra.Command{
	Use:   "crema",
	Short: "SSH agent and Git signing with Mokapot JavaCard",
	Long: `crema provides SSH agent and Git commit signing backed by a Mokapot JavaCard applet.
Private keys never leave the card.

Use 'crema serve' to start the SSH agent, and 'crema' as gpg.ssh.program for Git signing.`,
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

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(signCmd)
}

// connectCard is a shared helper used by subcommands that need a card connection.
func connectCard() (*card.Card, error) {
	return card.Connect(readerFlag)
}
