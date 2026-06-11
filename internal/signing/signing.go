// Package signing provides the owner's payload-provenance signature: an Ed25519
// keypair generated OFF the watching host (at seal time) whose public half goes
// on the recovery card. The owner signs the sealed vault ciphertext so a forged
// or substituted vault is detectable by the beneficiary at recovery.
//
// This closes threat-model H3 precisely because signing happens when the owner is
// present and verification happens at recovery — neither step needs a secret on
// the watch host, so a host compromise cannot forge a vault the beneficiary
// trusts. (Contrast H4, where a host-resident MAC key buys nothing.)
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	privPrefix = "dms-sign-sk-"
	pubPrefix  = "dms-sign-pk-"
)

// Keypair is an Ed25519 owner signing identity, encoded as prefixed base64url.
type Keypair struct {
	Private string // dms-sign-sk-...
	Public  string // dms-sign-pk-...
}

// Generate creates a fresh Ed25519 signing keypair.
func Generate() (Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Keypair{}, fmt.Errorf("generate signing key: %w", err)
	}
	return Keypair{
		Private: privPrefix + b64(priv),
		Public:  pubPrefix + b64(pub),
	}, nil
}

// Sign returns a detached Ed25519 signature over payload using the private key.
func Sign(privateKey string, payload []byte) ([]byte, error) {
	priv, err := decodePriv(privateKey)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, payload), nil
}

// Verify checks a detached signature over payload against the public key.
func Verify(publicKey string, payload, sig []byte) error {
	pub, err := decodePub(publicKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("signature does not verify (vault may be forged or tampered)")
	}
	return nil
}

// SignToken produces a signed check-in token asserting the owner was alive at
// `when`. Format: "<RFC3339 time>\n<base64url signature over the time bytes>".
// Because only the owner's private key can produce a valid token, a process that
// merely runs the binary cannot forge proof-of-life (threat model H5).
func SignToken(privateKey string, when time.Time) ([]byte, error) {
	ts := when.UTC().Format(time.RFC3339)
	sig, err := Sign(privateKey, []byte(ts))
	if err != nil {
		return nil, err
	}
	return []byte(ts + "\n" + b64(sig)), nil
}

// VerifyToken checks a check-in token against the public key and returns the
// asserted time. It errors if the signature is absent, malformed, or invalid.
func VerifyToken(publicKey string, token []byte) (time.Time, error) {
	parts := strings.SplitN(strings.TrimSpace(string(token)), "\n", 2)
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("malformed check-in token")
	}
	ts, sigB64 := parts[0], parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return time.Time{}, fmt.Errorf("decode token signature: %w", err)
	}
	if err := Verify(publicKey, []byte(ts), sig); err != nil {
		return time.Time{}, err
	}
	when, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse token time: %w", err)
	}
	return when, nil
}

// PublicFor derives the public key string from a private signing key.
func PublicFor(privateKey string) (string, error) {
	priv, err := decodePriv(privateKey)
	if err != nil {
		return "", err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return pubPrefix + b64(pub), nil
}

// decodePriv parses a prefixed private key into an ed25519 key.
func decodePriv(s string) (ed25519.PrivateKey, error) {
	raw, err := decode(s, privPrefix)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad signing private key length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// decodePub parses a prefixed public key into an ed25519 key.
func decodePub(s string) (ed25519.PublicKey, error) {
	raw, err := decode(s, pubPrefix)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad signing public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// decode strips the prefix and base64url-decodes the remainder.
func decode(s, prefix string) ([]byte, error) {
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("not a %s key", prefix)
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
}

// b64 encodes bytes as raw (unpadded) base64url.
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
