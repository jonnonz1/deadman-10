package custody_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/custody"
	"github.com/jonnonz1/deadman-10/internal/timelock"
)

// TestReArmKeepsSharesValid is the H7 fix: re-arming pushes the unlock round
// forward by re-timelocking the SAME share, WITHOUT regenerating the key — so the
// beneficiary's already-distributed shares still reconstruct the vault.
func TestReArmKeepsSharesValid(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("liveness-coupled payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	net := timelock.NewFakeNetwork()
	_, ownerRecipient := newAgeKey(t)

	armed, err := custody.Arm(custody.ArmConfig{
		Source:         src,
		VaultPath:      filepath.Join(dir, "vault.age"),
		OwnerRecipient: ownerRecipient,
		ShamirN:        3,
		ShamirK:        2,
		Network:        net,
		UnlockRound:    net.Current(time.Now()) + 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(armed.RawTimelockShare) == 0 {
		t.Fatal("Arm must expose the raw timelock share so re-arm can re-lock it")
	}

	// Re-arm to a later round, reusing the same raw share (no key regeneration).
	laterRound := net.Current(time.Now()) + 100000
	rearmed, err := custody.ReArm(custody.ReArmConfig{
		RawTimelockShare: armed.RawTimelockShare,
		Network:          net,
		UnlockRound:      laterRound,
	})
	if err != nil {
		t.Fatalf("ReArm: %v", err)
	}
	if rearmed.UnlockRound != laterRound {
		t.Errorf("re-armed round = %d, want %d", rearmed.UnlockRound, laterRound)
	}

	// The beneficiary's ORIGINAL shares + the RE-ARMED timelocked share must still
	// reconstruct the original vault once the later round opens.
	net.PublishUpTo(laterRound)
	out := filepath.Join(dir, "recovered")
	if _, err := custody.Recover(custody.RecoverConfig{
		VaultPath:         armed.VaultPath,
		TimelockedShare:   rearmed.TimelockedShare,
		BeneficiaryShares: armed.BeneficiaryShares, // unchanged from original Arm
		Network:           net,
		DestDir:           out,
	}); err != nil {
		t.Fatalf("recover after re-arm with original shares: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "secret.txt"))
	if err != nil || string(got) != "liveness-coupled payload" {
		t.Fatalf("re-armed recovery wrong: %q err=%v", got, err)
	}
}

// TestReArmEarlierRoundStillLockedUntilThen sanity-checks that after re-arming to
// a later round, the share is not yet openable before that round.
func TestReArmNotOpenableBeforeRound(t *testing.T) {
	net := timelock.NewFakeNetwork()
	dir := t.TempDir()
	src := filepath.Join(dir, "s.txt")
	os.WriteFile(src, []byte("x"), 0o600)
	armed, _ := custody.Arm(custody.ArmConfig{
		Source: src, VaultPath: filepath.Join(dir, "v.age"),
		ShamirN: 3, ShamirK: 2, Network: net, UnlockRound: net.Current(time.Now()) + 10,
	})
	later := net.Current(time.Now()) + 500000
	rearmed, err := custody.ReArm(custody.ReArmConfig{
		RawTimelockShare: armed.RawTimelockShare, Network: net, UnlockRound: later,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Publish only up to a round between the two; the re-armed share must stay locked.
	net.PublishUpTo(later - 1)
	if _, err := timelock.OpenFromRound(net, rearmed.TimelockedShare); err == nil {
		t.Fatal("re-armed share opened before its round")
	}
}
