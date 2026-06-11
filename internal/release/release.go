// Package release defines what happens when the switch fires: the ciphertext is
// handed to a Publisher (file, or Arweave behind the same interface) and a
// Notifier is told. Both are interfaces so storage and delivery can be swapped
// without touching the engine; the Releaser ties them together and satisfies
// engine.Releaser.
package release

import (
	"fmt"
	"os"
	"time"
)

// Publisher writes the released ciphertext somewhere durable and returns a
// locator (a path, URL, or transaction id). Implementations must never see
// plaintext — only the already-encrypted vault bytes. publishID is a stable
// idempotency key for one fire event: wrapping a publisher in Idempotent ensures
// the same publishID is uploaded at most once, even across crashes/retries.
type Publisher interface {
	Publish(ciphertext []byte, publishID string, tags map[string]string) (locator string, err error)
}

// Notifier delivers a human-facing message about a switch event.
type Notifier interface {
	Notify(level, subject, body string) error
}

// Releaser performs the fire side effects: publish the vault, then notify.
type Releaser struct {
	vaultPath string
	publisher Publisher
	notifier  Notifier
}

// New builds a Releaser over a vault file, a publisher, and a notifier.
func New(vaultPath string, publisher Publisher, notifier Notifier) *Releaser {
	return &Releaser{vaultPath: vaultPath, publisher: publisher, notifier: notifier}
}

// Release reads the vault ciphertext, publishes it under a stable publishID, and
// emits a FIRE notification. It satisfies engine.Releaser. The publishID makes
// the publish idempotent (see Idempotent): a crash-and-retry of the same fire
// reuses the id and never double-publishes to an irreversible paid backend.
func (r *Releaser) Release(publishID string, elapsed time.Duration) error {
	ciphertext, err := os.ReadFile(r.vaultPath)
	if err != nil {
		return fmt.Errorf("read vault: %w", err)
	}
	loc, err := r.publisher.Publish(ciphertext, publishID, nil)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if r.notifier != nil {
		body := fmt.Sprintf("No check-in for %s. Vault released to %s. Only the beneficiary key can open it.",
			elapsed.Round(time.Minute), loc)
		// The fire already happened (publish succeeded). A failed notification is
		// LOGGED, never fatal — gating fire completion on notify success would let
		// a dead webhook re-trigger the fire path forever (a suppression/duplication
		// vector). The publish is the irreversible act; notification is best-effort.
		if err := r.notifier.Notify("FIRE", "Dead-man switch FIRED", body); err != nil {
			fmt.Fprintf(os.Stderr, "warning: FIRE notification failed (vault WAS released to %s): %v\n", loc, err)
		}
	}
	return nil
}
