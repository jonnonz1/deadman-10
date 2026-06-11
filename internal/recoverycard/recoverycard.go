// Package recoverycard renders the printable instructions a beneficiary needs to
// open the vault. The cypherpunk literature is unanimous that untested, missing,
// or unclear recovery instructions are the most common point of total failure, so
// this card aims to be self-contained and survivable for years.
package recoverycard

import (
	"fmt"
	"strings"
)

// Mode is which custody model the switch uses.
type Mode string

const (
	ModeSimple   Mode = "simple"   // vault encrypted directly to a beneficiary age key
	ModeTimelock Mode = "timelock" // share-timelock construction (no-operator)
)

// Data is everything the card needs to render.
type Data struct {
	OwnerName       string
	BeneficiaryName string
	Mode            Mode

	// OwnerSignPublic is the owner's signing public key; the beneficiary uses it
	// to verify the vault's provenance (that it really is the owner's).
	OwnerSignPublic string

	// Timelock mode:
	ShamirK     int
	ShamirN     int
	UnlockRound uint64
	UnlockHuman string
	Locators    []string // where the vault / timelocked share is published
	Gateways    []string // gateways that can serve the data
}

// Render returns the full recovery card as plain text.
func Render(d Data) string {
	var b strings.Builder
	line := strings.Repeat("=", 72)
	b.WriteString(line + "\n")
	b.WriteString("  DEADMAN-10 RECOVERY CARD\n")
	if d.BeneficiaryName != "" {
		fmt.Fprintf(&b, "  For: %s — recovery instructions for %s's encrypted vault\n", d.BeneficiaryName, d.OwnerName)
	} else {
		fmt.Fprintf(&b, "  Recovery instructions for %s's encrypted vault\n", d.OwnerName)
	}
	b.WriteString(line + "\n\n")
	b.WriteString("If you are reading this, you may need to recover " + d.OwnerName + "'s vault.\n")
	b.WriteString("Everything below was encrypted; these instructions alone reveal nothing.\n\n")

	if d.Mode == ModeTimelock {
		renderTimelock(&b, d)
	} else {
		renderSimple(&b, d)
	}

	if d.OwnerSignPublic != "" {
		b.WriteString("\nPROVENANCE: verify the vault really is " + d.OwnerName + "'s before trusting it.\n")
		b.WriteString("Owner signing public key:\n  " + d.OwnerSignPublic + "\n")
		b.WriteString("`dms verify` checks the vault.age.sig signature against this key and\n")
		b.WriteString("refuses a forged or tampered vault.\n")
	}

	b.WriteString("\n" + line + "\n")
	b.WriteString("KEEP THIS CARD SAFE. Print it. Store copies in separate places.\n")
	b.WriteString("Tooling: github.com/jonnonz1/deadman-10 — `dms` is a single binary.\n")
	b.WriteString(line + "\n")
	return b.String()
}

// renderTimelock writes the share-timelock recovery steps.
func renderTimelock(b *strings.Builder, d Data) {
	fmt.Fprintf(b, "CUSTODY: %d-of-%d Shamir shares of the vault key.\n", d.ShamirK, d.ShamirN)
	fmt.Fprintf(b, "You hold %d share file(s): share-beneficiary-1.txt ... (store OFFLINE).\n", d.ShamirK-1)
	b.WriteString("One more share is TIMELOCKED to the public drand network and becomes\n")
	if d.UnlockHuman != "" {
		fmt.Fprintf(b, "available automatically at: %s (drand round %d).\n", d.UnlockHuman, d.UnlockRound)
	} else {
		fmt.Fprintf(b, "available automatically at drand round %d.\n", d.UnlockRound)
	}
	b.WriteString("\nWHERE THE DATA IS (the vault ciphertext and the timelocked share):\n")
	if len(d.Locators) == 0 {
		b.WriteString("  (fill in the published locations / Arweave tx ids / ArNS name)\n")
	}
	for _, l := range d.Locators {
		fmt.Fprintf(b, "  - %s\n", l)
	}
	if len(d.Gateways) > 0 {
		b.WriteString("  Reachable via gateways: " + strings.Join(d.Gateways, ", ") + "\n")
	}
	b.WriteString("\nHOW TO RECOVER:\n")
	b.WriteString("  1. Install dms (single binary). Put your beneficiary share file(s) and\n")
	b.WriteString("     the timelocked share (share-timelocked.age) in one folder.\n")
	b.WriteString("  2. Wait until the unlock time above has passed.\n")
	b.WriteString("  3. Run:  dms timelock-recover --out ./recovered\n")
	b.WriteString("  4. Your recovered files appear under ./recovered.\n")
	b.WriteString("\nWHY THIS IS SAFE: the timelocked share is public, but ONE share alone\n")
	b.WriteString("reveals nothing. Recovery needs it PLUS your offline shares.\n")
	b.WriteString("\n⚠ IF YOU LOSE YOUR SHARE FILES, the vault CANNOT BE RECOVERED by anyone.\n")
	b.WriteString("  Make copies. Keep them somewhere only you can reach.\n")
}

// renderSimple writes the Level-0 (beneficiary-key) recovery steps.
func renderSimple(b *strings.Builder, d Data) {
	b.WriteString("CUSTODY: the vault is encrypted directly to your beneficiary key.\n")
	b.WriteString("You hold one secret key file (beneficiary.key). Store it OFFLINE.\n")
	b.WriteString("\nWHERE THE DATA IS:\n")
	if len(d.Locators) == 0 {
		b.WriteString("  (the released vault.age — fill in where it will be delivered)\n")
	}
	for _, l := range d.Locators {
		fmt.Fprintf(b, "  - %s\n", l)
	}
	b.WriteString("\nHOW TO RECOVER:\n")
	b.WriteString("  1. Install dms. Place vault.age and your beneficiary.key in one folder.\n")
	b.WriteString("  2. Run:  dms verify --id beneficiary.key --out ./recovered\n")
	b.WriteString("  3. Your recovered files appear under ./recovered.\n")
	b.WriteString("\n⚠ IF YOU LOSE beneficiary.key, the vault CANNOT BE RECOVERED by anyone.\n")
}
