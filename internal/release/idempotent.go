package release

import (
	"os"
	"path/filepath"
	"strings"
)

// Idempotent wraps a Publisher so that a given publishID is uploaded at most
// once, ever. It persists a small receipt (the returned locator) per publishID
// in a durable directory. This is the H5 guard: if the fire path crashes after a
// successful upload but before recording success, the next tick reuses the
// receipt instead of paying for a duplicate permanent upload.
type Idempotent struct {
	inner       Publisher
	receiptsDir string
}

// NewIdempotent wraps inner, persisting receipts under receiptsDir.
func NewIdempotent(inner Publisher, receiptsDir string) *Idempotent {
	return &Idempotent{inner: inner, receiptsDir: receiptsDir}
}

// receiptPath returns the durable receipt file for a publishID.
func (p *Idempotent) receiptPath(publishID string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(publishID)
	return filepath.Join(p.receiptsDir, "publish-"+safe+".receipt")
}

// Publish uploads via the inner publisher unless a receipt already records this
// publishID, in which case the stored locator is returned without re-uploading.
func (p *Idempotent) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	receipt := p.receiptPath(publishID)
	if b, err := os.ReadFile(receipt); err == nil {
		return strings.TrimSpace(string(b)), nil // already published; never re-upload
	}
	loc, err := p.inner.Publish(ciphertext, publishID, tags)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(p.receiptsDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(receipt, []byte(loc+"\n"), 0o600); err != nil {
		return "", err
	}
	return loc, nil
}
