package release

import (
	"fmt"

	"github.com/jonnonz1/deadman-10/internal/arweave"
)

// ArweavePublisher uploads the released ciphertext to Arweave permanent storage
// via the dependency-free internal/arweave client. It only handles single-chunk
// payloads (≤ 256 KiB), which a deadman vault always is; larger data is rejected
// rather than mis-chunked. Wrap it in Idempotent so a retried fire never pays for
// a duplicate permanent upload.
type ArweavePublisher struct {
	walletPath string
	gateway    string
}

// NewArweavePublisher returns a publisher that signs with the JWK at walletPath
// and posts to the given gateway (or arlocal devnet) URL.
func NewArweavePublisher(walletPath, gateway string) *ArweavePublisher {
	return &ArweavePublisher{walletPath: walletPath, gateway: gateway}
}

// Publish signs and submits a Format-2 transaction carrying the ciphertext and
// returns the gateway URL of the resulting transaction.
func (p *ArweavePublisher) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	if len(ciphertext) > arweave.MaxChunkSize {
		return "", fmt.Errorf("payload too large for single-chunk upload: %d bytes (max %d)",
			len(ciphertext), arweave.MaxChunkSize)
	}
	wallet, err := arweave.LoadWallet(p.walletPath)
	if err != nil {
		return "", fmt.Errorf("load arweave wallet: %w", err)
	}
	client := arweave.NewClient(p.gateway)
	reward, err := client.Price(len(ciphertext))
	if err != nil {
		return "", fmt.Errorf("get price: %w", err)
	}
	anchor, err := client.Anchor()
	if err != nil {
		return "", fmt.Errorf("get anchor: %w", err)
	}

	// Tags are kept minimal to avoid signalling "owner presumed dead" publicly
	// (threat model D2); only a content type is set.
	txTags := []arweave.Tag{{Name: "Content-Type", Value: "application/octet-stream"}}
	tx := arweave.NewTransaction(ciphertext, anchor, reward, txTags)
	if err := tx.Sign(wallet); err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}
	id, err := client.Submit(tx)
	if err != nil {
		return "", fmt.Errorf("submit tx: %w", err)
	}
	return p.gateway + "/" + id, nil
}
