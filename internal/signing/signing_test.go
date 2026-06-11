package signing_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/signing"
)

// TestGenerateAndRoundTrip: a freshly generated owner signing key signs a payload
// and the matching public key verifies it.
func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.Private, "dms-sign-sk-") || !strings.HasPrefix(kp.Public, "dms-sign-pk-") {
		t.Fatalf("unexpected key encoding: %q / %q", kp.Private, kp.Public)
	}
	payload := []byte("the vault ciphertext bytes")
	sig, err := signing.Sign(kp.Private, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(kp.Public, payload, sig); err != nil {
		t.Errorf("valid signature failed to verify: %v", err)
	}
}

// TestForgeryDetected: a payload signed by a different key (the attacker's) must
// NOT verify against the owner's public key. This is the H3 property — a
// substituted vault is detectable.
func TestForgeryDetected(t *testing.T) {
	owner, _ := signing.Generate()
	attacker, _ := signing.Generate()

	forged := []byte("malicious replacement vault")
	sig, _ := signing.Sign(attacker.Private, forged)

	if err := signing.Verify(owner.Public, forged, sig); err == nil {
		t.Fatal("forged vault verified against owner key — provenance broken")
	}
}

// TestTamperedPayloadFailsVerify: flipping any ciphertext byte invalidates the
// signature.
func TestTamperedPayloadFailsVerify(t *testing.T) {
	kp, _ := signing.Generate()
	payload := []byte("original ciphertext")
	sig, _ := signing.Sign(kp.Private, payload)

	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xff
	if err := signing.Verify(kp.Public, tampered, sig); err == nil {
		t.Fatal("tampered payload verified — integrity broken")
	}
}

// TestPublicForPrivate derives the public key from a private signing key.
func TestPublicForPrivate(t *testing.T) {
	kp, _ := signing.Generate()
	pub, err := signing.PublicFor(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.Public {
		t.Errorf("derived public %q != %q", pub, kp.Public)
	}
}

// TestCheckinTokenRoundTrip: a signed check-in token verifies and yields back the
// asserted time; this is the authenticated proof-of-life (H5).
func TestCheckinTokenRoundTrip(t *testing.T) {
	kp, _ := signing.Generate()
	when := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)
	tok, err := signing.SignToken(kp.Private, when)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signing.VerifyToken(kp.Public, tok)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if !got.Equal(when) {
		t.Errorf("token time = %v, want %v", got, when)
	}
}

// TestForgedTokenRejected: a token signed by a non-owner key must not verify —
// so a process without the owner key cannot fake a check-in.
func TestForgedTokenRejected(t *testing.T) {
	owner, _ := signing.Generate()
	attacker, _ := signing.Generate()
	tok, _ := signing.SignToken(attacker.Private, time.Now())
	if _, err := signing.VerifyToken(owner.Public, tok); err == nil {
		t.Fatal("forged check-in token verified — H5 broken")
	}
}

// TestTamperedTokenTimeRejected: editing the timestamp in a token invalidates it.
func TestTamperedTokenTimeRejected(t *testing.T) {
	kp, _ := signing.Generate()
	tok, _ := signing.SignToken(kp.Private, time.Now())
	tok[0] ^= 0xff // corrupt the payload
	if _, err := signing.VerifyToken(kp.Public, tok); err == nil {
		t.Fatal("tampered token verified")
	}
}

// TestRejectsMalformedKeys: garbage keys error rather than panic.
func TestRejectsMalformedKeys(t *testing.T) {
	if _, err := signing.Sign("not-a-key", []byte("x")); err == nil {
		t.Error("expected error signing with malformed key")
	}
	if err := signing.Verify("not-a-key", []byte("x"), []byte("sig")); err == nil {
		t.Error("expected error verifying with malformed key")
	}
}
