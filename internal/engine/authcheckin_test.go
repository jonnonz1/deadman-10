package engine_test

import (
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/engine"
	"github.com/jonnonz1/deadman-10/internal/signing"
)

// TestAuthCheckinAcceptsValidToken: with a check-in public key configured, a
// token signed by the matching private key is accepted as proof of life.
func TestAuthCheckinAcceptsValidToken(t *testing.T) {
	kp, _ := signing.Generate()
	clk := &fixedClock{t: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{
		StateDir:      t.TempDir(),
		WarnAfter:     10 * time.Minute,
		FireAfter:     20 * time.Minute,
		CheckinPubKey: kp.Public,
	}, clk)

	tok, _ := signing.SignToken(kp.Private, clk.Now())
	if err := e.AuthCheckin(tok); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if e.Stage() != engine.StageHealthy {
		t.Errorf("after authed check-in stage = %v, want HEALTHY", e.Stage())
	}
}

// TestAuthCheckinRejectsForgedToken: a token from a different key is refused, so
// a process without the owner key cannot suppress the switch (H5).
func TestAuthCheckinRejectsForgedToken(t *testing.T) {
	owner, _ := signing.Generate()
	attacker, _ := signing.Generate()
	clk := &fixedClock{t: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{
		StateDir:      t.TempDir(),
		WarnAfter:     10 * time.Minute,
		FireAfter:     20 * time.Minute,
		CheckinPubKey: owner.Public,
	}, clk)

	tok, _ := signing.SignToken(attacker.Private, clk.Now())
	if err := e.AuthCheckin(tok); err == nil {
		t.Fatal("forged check-in token accepted — H5 broken")
	}
	// A forged check-in must not have advanced liveness.
	if _, ok := e.LastCheckin(); ok {
		t.Error("forged check-in advanced last_checkin")
	}
}

// TestAuthCheckinRejectsStaleReplay: a token older than the monotonic floor (a
// replayed old check-in) is refused, so capturing one old token can't keep the
// switch alive forever.
func TestAuthCheckinRejectsStaleReplay(t *testing.T) {
	kp, _ := signing.Generate()
	clk := &fixedClock{t: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{
		StateDir:      t.TempDir(),
		WarnAfter:     10 * time.Minute,
		FireAfter:     20 * time.Minute,
		CheckinPubKey: kp.Public,
	}, clk)

	// First, a fresh valid check-in advances the floor.
	tokNow, _ := signing.SignToken(kp.Private, clk.Now())
	if err := e.AuthCheckin(tokNow); err != nil {
		t.Fatal(err)
	}
	// Replay an OLDER token (signed for an earlier time): must be rejected.
	old := clk.Now().Add(-1 * time.Hour)
	tokOld, _ := signing.SignToken(kp.Private, old)
	if err := e.AuthCheckin(tokOld); err == nil {
		t.Fatal("stale replayed token accepted — replay protection missing")
	}
}

// TestPlainCheckinRejectedWhenAuthRequired: when a check-in key is configured,
// the unauthenticated Checkin path must be refused so it can't bypass auth.
func TestPlainCheckinRejectedWhenAuthRequired(t *testing.T) {
	kp, _ := signing.Generate()
	clk := &fixedClock{t: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{
		StateDir:      t.TempDir(),
		WarnAfter:     10 * time.Minute,
		FireAfter:     20 * time.Minute,
		CheckinPubKey: kp.Public,
	}, clk)
	if err := e.Checkin(); err == nil {
		t.Fatal("plain Checkin should be refused when a check-in key is configured")
	}
}
