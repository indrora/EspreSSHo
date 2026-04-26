package crema

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/indrora/EspreSSHo/barista/internal/sshagent"
)

var signCmd = &cobra.Command{
	Use:    "sign",
	Short:  "Sign data (Git integration)",
	Hidden: true,
	Long: `sign reads data from stdin, signs it using a key on the card, and outputs
the signature. This is intended to be used as gpg.ssh.program for Git signing.`,
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	// Read the data to sign from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	cardConn, err := connectCard()
	if err != nil {
		return fmt.Errorf("connect to card: %w", err)
	}
	defer cardConn.Close()

	cardAgent, err := sshagent.New(cardConn)
	if err != nil {
		return fmt.Errorf("init agent: %w", err)
	}

	// Get the list of keys available on the card
	keys, err := cardAgent.List()
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keys found on card")
	}

	// Use the first key for signing (this is a simplification)
	// In a more complete implementation, Git would specify which key to use.
	firstKey, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// Sign the data
	sig, err := cardAgent.Sign(firstKey, data)
	if err != nil {
		return fmt.Errorf("sign data: %w", err)
	}

	// Output the signature in the format expected by Git.
	// Git expects a base64-encoded signature blob prefixed with the algorithm name.
	fmt.Printf("%s %x\n", sig.Format, sig.Blob)

	return nil
}
