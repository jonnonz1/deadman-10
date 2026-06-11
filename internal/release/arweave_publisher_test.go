package release_test

import (
	"strings"
	"testing"

	"github.com/jonnonz1/deadman-10/internal/release"
)

// TestArweavePublisherRejectsOversize: the single-chunk uploader must refuse data
// larger than one Arweave chunk rather than produce a malformed (mis-chunked) tx.
func TestArweavePublisherRejectsOversize(t *testing.T) {
	p := release.NewArweavePublisher("/nonexistent/wallet.json", "http://127.0.0.1:1985")
	big := make([]byte, 300_000) // > 256 KiB single-chunk limit
	if _, err := p.Publish(big, "fire-x", nil); err == nil {
		t.Fatal("expected oversize payload to be rejected")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected a size error, got: %v", err)
	}
}

// TestArweavePublisherNeedsWallet: without a readable wallet, Publish must fail
// clearly (not silently no-op).
func TestArweavePublisherNeedsWallet(t *testing.T) {
	p := release.NewArweavePublisher("/nonexistent/wallet.json", "http://127.0.0.1:1985")
	if _, err := p.Publish([]byte("small"), "fire-x", nil); err == nil {
		t.Fatal("expected missing-wallet error")
	}
}
