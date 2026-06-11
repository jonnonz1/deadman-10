package release

import (
	"fmt"
	"os"
	"path/filepath"
)

// FilePublisher writes ciphertext to a local outbox directory. This is the
// default, network-free storage leg.
type FilePublisher struct{ dir string }

// NewFilePublisher returns a publisher that writes into dir.
func NewFilePublisher(dir string) *FilePublisher { return &FilePublisher{dir: dir} }

// Publish writes the ciphertext as vault.age in the outbox and returns its path.
func (p *FilePublisher) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(p.dir, "vault.age")
	if err := os.WriteFile(out, ciphertext, 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// DryRunPublisher performs no real write. It reports what it would have done,
// which is the safety default for irreversible backends like Arweave.
type DryRunPublisher struct{ backend string }

// NewDryRunPublisher returns a no-op publisher labelled with the backend it
// stands in for.
func NewDryRunPublisher(backend string) *DryRunPublisher {
	return &DryRunPublisher{backend: backend}
}

// Publish returns a dry-run locator and writes nothing.
func (p *DryRunPublisher) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	return fmt.Sprintf("dry-run://%s (%d bytes, not uploaded)", p.backend, len(ciphertext)), nil
}
