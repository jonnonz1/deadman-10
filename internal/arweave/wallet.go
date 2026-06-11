package arweave

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// Wallet is an Arweave RSA key loaded from a JWK file. The public modulus (n) is
// the wallet's "owner" and its SHA-256 (base64url) is the address.
type Wallet struct {
	key *rsa.PrivateKey
}

// jwk is the subset of the RFC 7517 JWK fields Arweave uses (RSA, base64url).
type jwk struct {
	N  string `json:"n"`
	E  string `json:"e"`
	D  string `json:"d"`
	P  string `json:"p"`
	Q  string `json:"q"`
	DP string `json:"dp"`
	DQ string `json:"dq"`
	QI string `json:"qi"`
}

// LoadWallet reads an Arweave JWK key file and returns a usable Wallet.
func LoadWallet(path string) (*Wallet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseWallet(b)
}

// ParseWallet builds a Wallet from raw JWK JSON.
func ParseWallet(b []byte) (*Wallet, error) {
	var j jwk
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("parse jwk: %w", err)
	}
	n := b64ToBig(j.N)
	e := b64ToBig(j.E)
	d := b64ToBig(j.D)
	if n == nil || e == nil || d == nil {
		return nil, fmt.Errorf("jwk missing n/e/d")
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{b64ToBig(j.P), b64ToBig(j.Q)},
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rsa key: %w", err)
	}
	key.Precompute()
	return &Wallet{key: key}, nil
}

// Owner returns the base64url-encoded RSA modulus (the tx "owner" field).
func (w *Wallet) Owner() string {
	return b64(w.key.N.Bytes())
}

// Address returns the wallet address: base64url(SHA-256(modulus)).
func (w *Wallet) Address() string {
	h := sha256.Sum256(w.key.N.Bytes())
	return b64(h[:])
}

// b64 encodes bytes as Arweave's raw (unpadded) base64url.
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64ToBig decodes a base64url field into a big.Int (nil on failure).
func b64ToBig(s string) *big.Int {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(raw)
}
