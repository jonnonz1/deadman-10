//go:build integration

package timelock_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/timelock"
)

// TestLiveQuicknetRoundTrip is the high-confidence proof: against the REAL drand
// quicknet beacon, timelock a share to a few seconds out, confirm it is locked
// now, wait for the round, and confirm it unlocks. Run with:
//
//	go test -tags=integration ./internal/timelock/ -run Live -v
func TestLiveQuicknetRoundTrip(t *testing.T) {
	net, err := timelock.QuicknetNetwork()
	if err != nil {
		t.Fatalf("connect quicknet: %v", err)
	}

	share := []byte("live-quicknet-shamir-share")
	unlockAt := time.Now().Add(8 * time.Second)
	round := net.Current(unlockAt)

	sealed, err := timelock.SealToRound(net, round, share)
	if err != nil {
		t.Fatalf("SealToRound: %v", err)
	}

	// Immediately: must be locked.
	if _, err := timelock.OpenFromRound(net, sealed); err == nil {
		t.Fatal("share unlocked too early against live beacon")
	}

	// Wait past the unlock time plus a margin for beacon propagation.
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		got, err := timelock.OpenFromRound(net, sealed)
		if err == nil {
			if !bytes.Equal(got, share) {
				t.Fatalf("unlocked mismatch: got %q want %q", got, share)
			}
			return // success
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("share never unlocked against live beacon within deadline")
}
