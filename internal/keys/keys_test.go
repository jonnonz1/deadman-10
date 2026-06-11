package keys_test

import (
	"strings"
	"testing"

	"github.com/jonnonz1/deadman-10/internal/keys"
)

// TestGenerateKeypairFormats checks generated keys have the expected age prefixes.
func TestGenerateKeypairFormats(t *testing.T) {
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.Private, "AGE-SECRET-KEY-1") {
		t.Errorf("private key bad prefix: %q", kp.Private)
	}
	if !strings.HasPrefix(kp.Public, "age1") {
		t.Errorf("public key bad prefix: %q", kp.Public)
	}
}

// TestKeypairsAreUnique ensures each generation is fresh.
func TestKeypairsAreUnique(t *testing.T) {
	a, _ := keys.Generate()
	b, _ := keys.Generate()
	if a.Private == b.Private || a.Public == b.Public {
		t.Error("two generations produced identical keys")
	}
}

// TestDeriveRecipient recovers the public key from a private identity string.
func TestDeriveRecipient(t *testing.T) {
	kp, _ := keys.Generate()
	pub, err := keys.RecipientFor(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.Public {
		t.Errorf("derived recipient %q != %q", pub, kp.Public)
	}
}
