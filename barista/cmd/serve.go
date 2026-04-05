package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"

	"github.com/indrora/EspreSSHo/barista/sshagent"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the SSH agent on a Unix socket",
	Long: `serve connects to the Mokapot card and starts an SSH agent on a Unix domain
socket. Set SSH_AUTH_SOCK to the socket path to use it with ssh, git, etc.

The socket path defaults to /tmp/barista-<pid>.sock. The shell eval line is
printed to stdout so you can do: eval $(barista serve)`,
	RunE: runServe,
}

var socketFlag string

func init() {
	serveCmd.Flags().StringVar(
		&socketFlag, "socket", "",
		"Unix socket path (default: /tmp/barista-<pid>.sock)",
	)
}

func runServe(cmd *cobra.Command, args []string) error {
	socketPath := socketFlag
	if socketPath == "" {
		socketPath = fmt.Sprintf("/tmp/barista-%d.sock", os.Getpid())
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

	// Remove any stale socket from a previous run.
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer os.Remove(socketPath)

	// Print the shell eval line so the user can set SSH_AUTH_SOCK.
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", socketPath)

	// Graceful shutdown on SIGINT / SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Accept returns an error when the listener is closed — that's our
			// shutdown signal, not a real error.
			select {
			case <-stop:
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go agent.ServeAgent(cardAgent, conn) //nolint:errcheck — errors are per-connection
	}
}
