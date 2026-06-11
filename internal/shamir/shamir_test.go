package shamir_test

import (
	"bytes"
	"testing"

	"github.com/jonnonz1/deadman-10/internal/shamir"
)

// TestSplitCombineRoundTrip is the core spec: any K of N shares rebuild the secret.
func TestSplitCombineRoundTrip(t *testing.T) {
	secret := []byte("master-key-32-bytes-of-entropy!!")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}
	// Exactly the threshold (3) must reconstruct.
	got, err := shamir.Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("reconstruction mismatch: got %q want %q", got, secret)
	}
}

// TestAnyThresholdSubset proves a non-contiguous K subset also reconstructs.
func TestAnyThresholdSubset(t *testing.T) {
	secret := []byte("another secret value")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	subset := [][]byte{shares[0], shares[2], shares[4]}
	got, err := shamir.Combine(subset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("subset reconstruction mismatch: got %q want %q", got, secret)
	}
}

// TestBelowThresholdFailsToReconstruct is the property the whole deadman design
// rests on: fewer than K shares must NOT reveal the secret. With K-1 shares the
// result must never equal the real secret (information-theoretic security).
func TestBelowThresholdFailsToReconstruct(t *testing.T) {
	secret := []byte("the-secret-that-must-stay-hidden")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Combine of K-1 shares either errors or yields a wrong value, but it must
	// never equal the real secret.
	got, err := shamir.Combine(shares[:2])
	if err == nil && bytes.Equal(got, secret) {
		t.Fatal("K-1 shares reconstructed the secret — confidentiality broken")
	}
}

// TestSingleLeakedShareRevealsNothing models the deadman scenario directly: one
// timelocked share becomes public. It must not reconstruct anything alone.
func TestSingleLeakedShareRevealsNothing(t *testing.T) {
	secret := []byte("vault master key")
	shares, err := shamir.Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := shamir.Combine(shares[:1])
	if err == nil && bytes.Equal(got, secret) {
		t.Fatal("single share revealed the secret — design is broken")
	}
}

// TestInvalidParams rejects nonsensical thresholds.
func TestInvalidParams(t *testing.T) {
	cases := []struct{ n, k int }{
		{1, 2}, // k > n
		{5, 0}, // k < 1
		{5, 1}, // k == 1 means no secrecy; reject to be safe
		{0, 0},
	}
	for _, c := range cases {
		if _, err := shamir.Split([]byte("x"), c.n, c.k); err == nil {
			t.Errorf("Split(n=%d,k=%d) should have errored", c.n, c.k)
		}
	}
}
