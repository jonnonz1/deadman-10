package main_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// writeFundedWallet generates a 4096-bit RSA JWK, writes it to path, mints devnet
// funds to its address on arlocal, and returns the address.
func writeFundedWallet(t *testing.T, path, arlocal string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	expBytes := func(e int) []byte {
		var b []byte
		for e > 0 {
			b = append([]byte{byte(e & 0xff)}, b...)
			e >>= 8
		}
		return b
	}
	jwk := map[string]string{
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
	b, _ := json.Marshal(jwk)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	addrHash := sha256.Sum256(key.N.Bytes())
	addr := base64.RawURLEncoding.EncodeToString(addrHash[:])
	http.Get(arlocal + "/mint/" + addr + "/1000000000000")
	return addr
}

// extractLocator pulls the gateway/<txid> URL out of the fire notifier output.
func extractLocator(out string) string {
	for f := range strings.FieldsSeq(out) {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return strings.TrimRight(f, ".")
		}
	}
	return ""
}
