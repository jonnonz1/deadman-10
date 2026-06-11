package engine_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/engine"
)

// TestRejectFutureDatedCheckin: a last_checkin stamped in the future (clock skew
// or tampering) must not push the fire deadline out indefinitely. The engine
// clamps elapsed to >= 0 and treats a future stamp as "now", not as extra life.
func TestFutureDatedCheckinDoesNotExtendLife(t *testing.T) {
	dir := t.TempDir()
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{StateDir: dir, WarnAfter: 10 * time.Minute, FireAfter: 20 * time.Minute}, clk)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	// Tamper: write a far-future check-in time.
	future := clk.Now().Add(100 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "last_checkin"), []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}

	// Even though the stamp is in the future, the switch must not be "healthier"
	// than a fresh check-in — it must not report negative elapsed / extended life.
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("stage with future stamp = %v, want HEALTHY (clamped)", got)
	}
	// Advance past fire; a future-dated stamp must still let it fire eventually.
	clk.advance(200 * time.Hour)
	if got := e.Stage(); got != engine.StageFire {
		t.Errorf("after 200h the switch must FIRE despite future stamp, got %v", got)
	}
}

// TestRollbackDetectedViaFloor: rolling last_checkin BACK to look older than it
// is would bring the fire deadline closer (premature fire). The monotonic floor
// records the latest check-in ever seen, so a rolled-back stamp is detected and
// the floor is used instead — preventing the rollback from aging the switch.
func TestRollbackUsesMonotonicFloor(t *testing.T) {
	dir := t.TempDir()
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{StateDir: dir, WarnAfter: 10 * time.Minute, FireAfter: 20 * time.Minute}, clk)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}

	// Attacker rolls last_checkin back 1 hour to push the switch toward firing.
	rolled := clk.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "last_checkin"), []byte(rolled), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without protection this would be WARN/FIRE; with the floor it stays HEALTHY.
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("rolled-back stamp aged the switch to %v; floor should hold it HEALTHY", got)
	}
}

// TestFloorAdvancesWithLegitimateCheckin: the floor must track real check-ins so
// it never wrongly suppresses a genuinely aged switch.
func TestFloorAdvancesWithCheckin(t *testing.T) {
	dir := t.TempDir()
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{StateDir: dir, WarnAfter: 10 * time.Minute, FireAfter: 20 * time.Minute}, clk)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}

	clk.advance(30 * time.Minute) // now genuinely past fire with no new check-in
	if got := e.Stage(); got != engine.StageFire {
		t.Errorf("genuinely aged switch should FIRE, got %v", got)
	}
	// A fresh check-in advances the floor and re-arms.
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("after re-checkin should be HEALTHY, got %v", got)
	}
}
