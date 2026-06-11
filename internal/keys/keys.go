// Package keys generates and inspects the age X25519 keypair the vault is
// encrypted to: the beneficiary key, whose public half lives on the host and
// whose private half is held offline by the recipient and never on the switch.
// (Owner provenance is a separate signing key — see internal/signing.)
package keys

import (
	"fmt"

	"filippo.io/age"
)

// Keypair is an age identity and its corresponding recipient public key.
type Keypair struct {
	Private string // AGE-SECRET-KEY-1...
	Public  string // age1...
}

// Generate creates a fresh X25519 keypair.
func Generate() (Keypair, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Keypair{}, fmt.Errorf("generate identity: %w", err)
	}
	return Keypair{Private: id.String(), Public: id.Recipient().String()}, nil
}

// RecipientFor derives the public recipient string from a private identity.
func RecipientFor(private string) (string, error) {
	id, err := age.ParseX25519Identity(private)
	if err != nil {
		return "", fmt.Errorf("parse identity: %w", err)
	}
	return id.Recipient().String(), nil
}
