package arweave

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// MaxChunkSize is Arweave's 256 KiB chunk size. Vault ciphertext is far smaller,
// so we only ever produce a single chunk and the simple single-leaf data_root;
// larger payloads are rejected by the publisher rather than mis-chunked.
const MaxChunkSize = 262144

// Tag is a transaction tag (stored base64url-encoded on the wire).
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Transaction is a Format-2 Arweave transaction ready to sign and post.
type Transaction struct {
	Format    int    `json:"format"`
	ID        string `json:"id"`
	LastTx    string `json:"last_tx"`
	Owner     string `json:"owner"`
	Tags      []Tag  `json:"tags"`
	Target    string `json:"target"`
	Quantity  string `json:"quantity"`
	DataSize  string `json:"data_size"`
	DataRoot  string `json:"data_root"`
	Data      string `json:"data"`
	Reward    string `json:"reward"`
	Signature string `json:"signature"`

	rawData []byte // unencoded payload, kept for signing/posting
}

// NewTransaction builds an unsigned Format-2 transaction carrying data, with the
// given anchor (last_tx), reward (winston), and tags. Tags are passed as plain
// strings and stored base64url-encoded, matching Arweave's wire format.
func NewTransaction(data []byte, lastTx, reward string, tags []Tag) *Transaction {
	encoded := make([]Tag, len(tags))
	for i, t := range tags {
		encoded[i] = Tag{Name: b64([]byte(t.Name)), Value: b64([]byte(t.Value))}
	}
	return &Transaction{
		Format:   2,
		LastTx:   lastTx,
		Tags:     encoded,
		Target:   "",
		Quantity: "0",
		DataSize: itoa(len(data)),
		DataRoot: b64(dataRoot(data)),
		Data:     b64(data),
		Reward:   reward,
		rawData:  data,
	}
}

// signatureData returns the deep-hash message signed for a Format-2 transaction,
// in the exact field order Arweave specifies.
func (tx *Transaction) signatureData(owner string) []byte {
	tagPairs := make([]DeepHashChunk, len(tx.Tags))
	for i, t := range tx.Tags {
		tagPairs[i] = listChunk([]DeepHashChunk{
			{Blob: mustB64(t.Name)},
			{Blob: mustB64(t.Value)},
		})
	}
	// Per arweave-js getSignatureData case 2: owner/target/last_tx/data_root are
	// base64-decoded to raw bytes, while format/quantity/reward/data_size are the
	// UTF-8 bytes of their string values.
	return DeepHash(listChunk([]DeepHashChunk{
		{Blob: []byte("2")},
		{Blob: mustB64(owner)},
		{Blob: mustB64(tx.Target)},
		{Blob: []byte(tx.Quantity)},
		{Blob: []byte(tx.Reward)},
		{Blob: mustB64(tx.LastTx)},
		listChunk(tagPairs),
		{Blob: []byte(tx.DataSize)},
		{Blob: mustB64(tx.DataRoot)},
	}))
}

// Sign computes the RSA-PSS signature and the transaction id with the wallet.
// The deep-hash message (itself SHA-384-based) is signed with RSA-PSS over
// SHA-256 and auto salt length, matching arweave-js's node-driver, which uses
// hashAlgorithm "sha256" and Node's default (max) PSS salt length.
func (tx *Transaction) Sign(w *Wallet) error {
	tx.Owner = w.Owner()
	msg := tx.signatureData(tx.Owner)
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPSS(rand.Reader, w.key, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return err
	}
	tx.Signature = b64(sig)
	id := sha256.Sum256(sig)
	tx.ID = b64(id[:])
	return nil
}

// JSON returns the wire-format bytes for POST /tx.
func (tx *Transaction) JSON() ([]byte, error) {
	return json.Marshal(tx)
}

// dataRoot computes the Format-2 merkle root for data that fits in one chunk:
// id = SHA256( SHA256(dataHash) || SHA256(intToBuffer(maxByteRange, 32)) ).
func dataRoot(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	dataHash := sha256.Sum256(data)
	noteBuf := note(len(data))
	idHashInput := append(sha256Of(dataHash[:]), sha256Of(noteBuf)...)
	root := sha256.Sum256(idHashInput)
	return root[:]
}

// note encodes n as a 32-byte big-endian buffer (Arweave NOTE_SIZE).
func note(n int) []byte {
	buf := make([]byte, 32)
	v := n
	for i := 31; i >= 0 && v > 0; i-- {
		buf[i] = byte(v & 0xff)
		v >>= 8
	}
	return buf
}

// sha256Of returns SHA-256(b).
func sha256Of(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// mustB64 decodes an Arweave base64url field to raw bytes (empty on failure).
func mustB64(s string) []byte {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return []byte{}
	}
	return raw
}

// itoa is a tiny strconv.Itoa wrapper kept local to avoid an import churn.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
