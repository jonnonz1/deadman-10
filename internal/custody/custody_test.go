package custody_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jonnonz1/deadman-10/internal/custody"
	"github.com/jonnonz1/deadman-10/internal/shamir"
	"github.com/jonnonz1/deadman-10/internal/timelock"
)

// newAgeKey returns a fresh age identity and recipient for test fixtures.
func newAgeKey(t *testing.T) (identity, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.String(), id.Recipient().String()
}

// armFixture seals a payload under the share-timelock construction with a fake
// drand network we control, returning the arming result and the network.
func armFixture(t *testing.T, n, k int) (*custody.Armed, *timelock.FakeNetwork, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("the real vault payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	net := timelock.NewFakeNetwork()
	round := net.Current(time.Now()) + 1000
	owner, _ := custodyKey(t)

	armed, err := custody.Arm(custody.ArmConfig{
		Source:         src,
		VaultPath:      filepath.Join(dir, "vault.age"),
		OwnerRecipient: owner, // owner can always recover while alive
		ShamirN:        n,
		ShamirK:        k,
		Network:        net,
		UnlockRound:    round,
	})
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	return armed, net, dir
}

// custodyKey returns a throwaway age recipient for the owner-recovery slot.
func custodyKey(t *testing.T) (recipient, identity string) {
	t.Helper()
	id, rec := newAgeKey(t)
	return rec, id
}

// TestArmProducesSharesAndTimelock checks the construction's outputs: N shares,
// exactly one timelocked, K-1 handed to the beneficiary, and a vault file.
func TestArmProducesShares(t *testing.T) {
	armed, _, _ := armFixture(t, 3, 2)
	if len(armed.BeneficiaryShares) != armed.K-1 {
		t.Errorf("beneficiary got %d shares, want K-1=%d", len(armed.BeneficiaryShares), armed.K-1)
	}
	if len(armed.TimelockedShare) == 0 {
		t.Error("expected a timelocked share")
	}
	if _, err := os.Stat(armed.VaultPath); err != nil {
		t.Errorf("vault not written: %v", err)
	}
}

// TestRecoverAfterUnlock is the end-to-end durable path: once the drand round is
// reached, the timelocked share + the beneficiary's K-1 shares reconstruct the
// vault key and open the payload.
func TestRecoverAfterUnlock(t *testing.T) {
	armed, net, dir := armFixture(t, 3, 2)

	// Before unlock: the timelocked share is not yet available -> cannot recover.
	if _, err := custody.Recover(custody.RecoverConfig{
		VaultPath:         armed.VaultPath,
		TimelockedShare:   armed.TimelockedShare,
		BeneficiaryShares: armed.BeneficiaryShares,
		Network:           net,
		DestDir:           filepath.Join(dir, "early"),
	}); err == nil {
		t.Fatal("recovered before timelock unlock — durability/secrecy broken")
	}

	// Publish the round; now recovery works.
	net.PublishUpTo(armed.UnlockRound)
	out := filepath.Join(dir, "recovered")
	if _, err := custody.Recover(custody.RecoverConfig{
		VaultPath:         armed.VaultPath,
		TimelockedShare:   armed.TimelockedShare,
		BeneficiaryShares: armed.BeneficiaryShares,
		Network:           net,
		DestDir:           out,
	}); err != nil {
		t.Fatalf("Recover after unlock: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the real vault payload" {
		t.Errorf("recovered payload mismatch: %q", got)
	}
}

// TestTimelockedShareAloneRevealsNothing is the §6.2 security property: even when
// the timelocked share becomes fully public at T, it is ONE Shamir share and
// reconstructs nothing without the beneficiary's K-1.
func TestTimelockedShareAloneRevealsNothing(t *testing.T) {
	armed, net, dir := armFixture(t, 3, 2)
	net.PublishUpTo(armed.UnlockRound) // simulate the world seeing the unlocked share

	// Open the timelocked share to its raw bytes — this is what the public gets.
	raw, err := timelock.OpenFromRound(net, armed.TimelockedShare)
	if err != nil {
		t.Fatalf("unlock share: %v", err)
	}

	// With ONLY that one share and zero beneficiary shares, recovery must fail.
	if _, err := custody.Recover(custody.RecoverConfig{
		VaultPath: armed.VaultPath,
		RawShares: [][]byte{raw}, // just the public share
		Network:   net,
		DestDir:   filepath.Join(dir, "attack"),
	}); err == nil {
		t.Fatal("a single public share opened the vault — the whole design is broken")
	}

	// And the raw share alone must not reconstruct the secret at the shamir layer.
	if _, err := shamir.Combine([][]byte{raw}); err == nil {
		t.Error("shamir combined a single share")
	}
}
