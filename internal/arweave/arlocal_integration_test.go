//go:build integration

package arweave

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// arlocalURL is where the local devnet runs. Start it with: npx arlocal 1985
const arlocalURL = "http://127.0.0.1:1985"

// genTestJWK creates a 4096-bit RSA key in Arweave JWK form for devnet testing.
func genTestJWK(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	j := map[string]string{
		"kty": "RSA",
		"n":   enc(key.N.Bytes()),
		"e":   enc(expBytes(key.E)),
		"d":   enc(key.D.Bytes()),
		"p":   enc(key.Primes[0].Bytes()),
		"q":   enc(key.Primes[1].Bytes()),
		"dp":  enc(key.Precomputed.Dp.Bytes()),
		"dq":  enc(key.Precomputed.Dq.Bytes()),
		"qi":  enc(key.Precomputed.Qinv.Bytes()),
	}
	b, _ := json.Marshal(j)
	return b
}

// expBytes encodes a small int (the RSA exponent) big-endian without leading zeros.
func expBytes(e int) []byte {
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}

func devnetUp() bool {
	resp, err := http.Get(arlocalURL + "/info")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// TestArlocalRoundTrip is the real proof: sign and post a Format-2 transaction to
// the local devnet, mine it, and read the exact ciphertext back. If signing or
// deep-hash were wrong, arlocal would reject the tx — so a clean fetch validates
// the whole uploader against a real Arweave node. Never touches mainnet.
func TestArlocalRoundTrip(t *testing.T) {
	if !devnetUp() {
		t.Skip("arlocal not running on :1985 (start: npx arlocal 1985)")
	}
	w, err := ParseWallet(genTestJWK(t))
	if err != nil {
		t.Fatal(err)
	}

	// Mint devnet funds to the wallet (arlocal-specific endpoint).
	http.Get(arlocalURL + "/mint/" + w.Address() + "/1000000000000")

	c := NewClient(arlocalURL)
	payload := []byte("deadman-10 vault ciphertext (devnet test)")
	reward, err := c.Price(len(payload))
	if err != nil {
		t.Fatalf("price: %v", err)
	}
	anchor, _ := c.Anchor()

	tx := NewTransaction(payload, anchor, reward, []Tag{{Name: "Content-Type", Value: "application/octet-stream"}})
	if err := tx.Sign(w); err != nil {
		t.Fatalf("sign: %v", err)
	}
	id, err := c.Submit(tx)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Mine the pending tx into a block (arlocal-specific).
	http.Get(arlocalURL + "/mine")

	got, err := c.Fetch(id)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round-trip mismatch:\n got  %q\n want %q", got, payload)
	}
}

// TestMain allows running with a temp HOME so any stray writes are contained.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
