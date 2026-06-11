package recoverycard_test

import (
	"strings"
	"testing"

	"github.com/jonnonz1/deadman-10/internal/recoverycard"
)

// TestCardContainsEssentials: the card must spell out everything a beneficiary
// needs years later — what they hold, where the vault is, and the exact steps.
func TestCardContainsEssentials(t *testing.T) {
	card := recoverycard.Render(recoverycard.Data{
		OwnerName:       "Alice",
		Mode:            recoverycard.ModeTimelock,
		ShamirK:         2,
		ShamirN:         3,
		UnlockRound:     1234567,
		UnlockHuman:     "2027-06-01 12:00 UTC",
		Locators:        []string{"https://arweave.net/abc123", "ar://deadman-alice"},
		Gateways:        []string{"https://arweave.net", "https://ar-io.dev"},
		BeneficiaryName: "Jane",
	})

	mustContain := []string{
		"Alice",                // whose switch
		"Jane",                 // who recovers
		"2-of-3",               // threshold
		"2027-06-01",           // when it unlocks
		"arweave.net/abc123",   // where the vault/share is
		"dms timelock-recover", // the actual command
		"share-beneficiary",    // what they must hold
	}
	for _, s := range mustContain {
		if !strings.Contains(card, s) {
			t.Errorf("recovery card missing %q\n---\n%s", s, card)
		}
	}
}

// TestCardWarnsAboutShareSafety: the card must tell the beneficiary the shares are
// the single point of failure — lose them and the vault is gone forever.
func TestCardWarnsAboutShareSafety(t *testing.T) {
	card := recoverycard.Render(recoverycard.Data{
		OwnerName: "Alice", Mode: recoverycard.ModeTimelock, ShamirK: 2, ShamirN: 3,
	})
	low := strings.ToLower(card)
	if !strings.Contains(low, "lose") && !strings.Contains(low, "cannot be recovered") {
		t.Errorf("card must warn that losing shares is unrecoverable:\n%s", card)
	}
}

// TestSimpleModeCard: the Level-0 (beneficiary-key) mode renders a card that
// references the beneficiary key rather than shares.
func TestSimpleModeCard(t *testing.T) {
	card := recoverycard.Render(recoverycard.Data{
		OwnerName:       "Alice",
		Mode:            recoverycard.ModeSimple,
		BeneficiaryName: "Jane",
	})
	if !strings.Contains(card, "dms verify") {
		t.Errorf("simple-mode card should reference `dms verify`:\n%s", card)
	}
	if strings.Contains(card, "share-beneficiary") {
		t.Errorf("simple-mode card should not mention Shamir shares:\n%s", card)
	}
}
