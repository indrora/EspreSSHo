package card

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ebfe/scard"

	"github.com/indrora/EspreSSHo/barista/internal/crypto"
)

// Card wraps an scard.Card connected to the Mokapot applet.
// Obtain one via Connect; release with Close when done.
// All operations are thread-safe through an internal mutex.
type Card struct {
	ctx    *scard.Context
	handle *scard.Card
	mu     sync.Mutex // Protects PC/SC transmit operations from concurrent access
}

// Connect establishes a PC/SC connection to a reader and selects the Mokapot applet.
//
// If readerName is empty, Connect picks the first available reader. If readerName
// is a prefix or substring of a reader name, it is matched case-insensitively.
// This lets callers pass a short hint (e.g. "ACS") instead of the full vendor string.
func Connect(readerName string) (*Card, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("establish PC/SC context: %w", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("list PC/SC readers: %w", err)
	}
	if len(readers) == 0 {
		ctx.Release()
		return nil, fmt.Errorf("no PC/SC readers found")
	}

	selectedReader, err := pickReader(readers, readerName)
	if err != nil {
		ctx.Release()
		return nil, err
	}

	handle, err := ctx.Connect(selectedReader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("connect to reader %q: %w", selectedReader, err)
	}

	card := &Card{ctx: ctx, handle: handle}

	if err := card.selectApplet(); err != nil {
		card.Close()
		return nil, fmt.Errorf("select Mokapot applet: %w", err)
	}

	return card, nil
}

// ListReaders returns the names of all available PC/SC readers. Useful for
// letting the user discover reader names to pass to --reader.
func ListReaders() ([]string, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("establish PC/SC context: %w", err)
	}
	defer ctx.Release()
	return ctx.ListReaders()
}

// Close disconnects from the card and releases the PC/SC context.
func (card *Card) Close() {
	if card.handle != nil {
		card.handle.Disconnect(scard.LeaveCard)
	}
	if card.ctx != nil {
		card.ctx.Release()
	}
}

// transmit sends a raw APDU byte slice and returns the response body and SW.
// This method is thread-safe.
func (card *Card) transmit(apdu []byte) ([]byte, uint16, error) {
	card.mu.Lock()
	defer card.mu.Unlock()

	resp, err := card.handle.Transmit(apdu)
	if err != nil {
		return nil, 0, fmt.Errorf("transmit APDU: %w", err)
	}
	if len(resp) < 2 {
		return nil, 0, fmt.Errorf("APDU response too short (%d bytes)", len(resp))
	}
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	return resp[:len(resp)-2], sw, nil
}

// selectApplet sends the ISO SELECT (by AID) APDU for the Mokapot applet.
func (card *Card) selectApplet() error {
	// SELECT FILE (by AID): CLA=00 INS=A4 P1=04 P2=00 Lc=len(AID) Data=AID
	apdu := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(AppletAID))}, AppletAID...)
	_, sw, err := card.transmit(apdu)
	if err != nil {
		return err
	}
	if sw != crypto.APDUSuccess {
		return fmt.Errorf("applet selection failed with status word: 0x%04X", sw)
	}
	return nil
}

// pickReader returns the first reader whose name contains readerName (case-insensitive).
// If readerName is empty, the first reader in the list is returned.
func pickReader(readers []string, readerName string) (string, error) {
	if readerName == "" {
		return readers[0], nil
	}
	needle := strings.ToLower(readerName)
	for _, name := range readers {
		if strings.Contains(strings.ToLower(name), needle) {
			return name, nil
		}
	}
	return "", fmt.Errorf("no reader matching %q — available: %v", readerName, readers)
}

// IsInitialized checks if the card has been initialized by attempting a simple operation.
// Returns true if initialized, false if uninitialized, or an error for other failures.
func (card *Card) IsInitialized() (bool, error) {
	// Try to list slots - this will fail with SW_SECURITY_STATUS_NOT_SATISFIED (0x6982)
	// on an uninitialized card, but succeed on an initialized card.
	_, err := card.ListSlots()
	if err != nil {
		if err == ErrCommandNotAllowed {
			return false, nil // Card is uninitialized
		}
		return false, err // Other error
	}
	return true, nil // Card is initialized
}
