package timelock_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/timelock"
)

// TestRoundForTime verifies the genesis/period round math from TIMELOCK.md:
//
//	round_for(T) = floor((T - genesis)/period) + 1
func TestRoundForTime(t *testing.T) {
	const genesis = int64(1692803367)
	const period = 3 * time.Second
	tc := timelock.RoundForTime

	at := func(secsAfterGenesis int64) time.Time {
		return time.Unix(genesis+secsAfterGenesis, 0)
	}
	cases := []struct {
		when time.Time
		want uint64
	}{
		{at(0), 1}, // genesis instant -> round 1
		{at(2), 1}, // within first 3s window
		{at(3), 2}, // next window
		{at(30), 11},
	}
	for _, c := range cases {
		if got := tc(c.when, genesis, period); got != c.want {
			t.Errorf("RoundForTime(+%v) = %d, want %d", c.when.Unix()-genesis, got, c.want)
		}
	}
}

// TestRoundForDurationFromNow checks the convenience used on each re-arm: given a
// duration in the future, compute the unlock round.
func TestRoundForDurationFromNow(t *testing.T) {
	const genesis = int64(1692803367)
	const period = 3 * time.Second
	now := time.Unix(genesis+90, 0) // round 31
	r := timelock.RoundForTime(now.Add(30*time.Second), genesis, period)
	// 90+30 = 120s -> floor(120/3)+1 = 41
	if r != 41 {
		t.Errorf("round for now+30s = %d, want 41", r)
	}
}

// TestSealUnlockableShareWithFakeNetwork proves the full wrap/unwrap path without
// touching the real drand network: a fake network whose signature for the target
// round is available lets us decrypt; the same before availability does not.
func TestSealUnlockableShareWithFakeNetwork(t *testing.T) {
	net := timelock.NewFakeNetwork()
	share := []byte("one-shamir-share-bytes")

	round := net.Current(time.Now()) + 100
	sealed, err := timelock.SealToRound(net, round, share)
	if err != nil {
		t.Fatalf("SealToRound: %v", err)
	}
	if bytes.Contains(sealed, share) {
		t.Fatal("sealed output must not contain the plaintext share")
	}

	// Before the round's signature is published, decryption must fail.
	if _, err := timelock.OpenFromRound(net, sealed); err == nil {
		t.Fatal("expected open to fail before round signature is available")
	}

	// Publish the signature for that round; now it opens.
	net.PublishUpTo(round)
	got, err := timelock.OpenFromRound(net, sealed)
	if err != nil {
		t.Fatalf("OpenFromRound after publish: %v", err)
	}
	if !bytes.Equal(got, share) {
		t.Errorf("unlocked = %q, want %q", got, share)
	}
}

// TestSealedFormatIsAge confirms the timelock output is an age-format file, so it
// composes with the rest of the toolchain.
func TestSealedFormatIsAge(t *testing.T) {
	net := timelock.NewFakeNetwork()
	sealed, err := timelock.SealToRound(net, net.Current(time.Now())+10, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(sealed), "age-encryption.org/v1") {
		t.Errorf("sealed output is not age format: %q", sealed[:min(40, len(sealed))])
	}
}
