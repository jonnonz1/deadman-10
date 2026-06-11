package engine_test

import (
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/engine"
)

// fixedClock lets tests control "now" so timer behaviour is deterministic.
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newEngine builds an engine over a temp state dir with a controllable clock and
// short thresholds: warn after 10 min, fire after 20 min.
func newEngine(t *testing.T) (*engine.Engine, *fixedClock) {
	t.Helper()
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	e := engine.New(engine.Config{
		StateDir:  t.TempDir(),
		WarnAfter: 10 * time.Minute,
		FireAfter: 20 * time.Minute,
	}, clk)
	return e, clk
}

// TestFreshCheckinIsHealthy: after a check-in, the switch is HEALTHY.
func TestFreshCheckinIsHealthy(t *testing.T) {
	e, _ := newEngine(t)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("stage = %v, want HEALTHY", got)
	}
}

// TestStageTransitions: HEALTHY -> WARN -> FIRE as time passes without check-in.
func TestStageTransitions(t *testing.T) {
	e, clk := newEngine(t)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	clk.advance(5 * time.Minute)
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("at 5min: %v, want HEALTHY", got)
	}
	clk.advance(10 * time.Minute) // 15 min total: past warn(10), before fire(20)
	if got := e.Stage(); got != engine.StageWarn {
		t.Errorf("at 15min: %v, want WARN", got)
	}
	clk.advance(10 * time.Minute) // 25 min total: past fire(20)
	if got := e.Stage(); got != engine.StageFire {
		t.Errorf("at 25min: %v, want FIRE", got)
	}
}

// TestWatchFiresOnce: Watch triggers fire exactly once, then is idempotent.
func TestWatchFiresOnce(t *testing.T) {
	e, clk := newEngine(t)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	clk.advance(25 * time.Minute)

	r1, err := e.Watch()
	if err != nil {
		t.Fatal(err)
	}
	if r1.Action != engine.ActionFired {
		t.Errorf("first watch action = %v, want fired", r1.Action)
	}
	r2, err := e.Watch()
	if err != nil {
		t.Fatal(err)
	}
	if r2.Action != engine.ActionNone {
		t.Errorf("second watch action = %v, want none (idempotent)", r2.Action)
	}
}

// TestWatchWarns: Watch in the warn window emits a warn action, not a fire.
func TestWatchWarns(t *testing.T) {
	e, clk := newEngine(t)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	clk.advance(15 * time.Minute)
	r, err := e.Watch()
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != engine.ActionWarned {
		t.Errorf("watch action = %v, want warned", r.Action)
	}
	if e.Fired() {
		t.Error("must not be fired in warn window")
	}
}

// TestCheckinReArmsAfterFire: a check-in clears the fired state and resets timer.
func TestCheckinReArmsAfterFire(t *testing.T) {
	e, clk := newEngine(t)
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	clk.advance(25 * time.Minute)
	if _, err := e.Watch(); err != nil {
		t.Fatal(err)
	}
	if !e.Fired() {
		t.Fatal("expected fired before re-arm")
	}
	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	if e.Fired() {
		t.Error("check-in must clear fired state")
	}
	if got := e.Stage(); got != engine.StageHealthy {
		t.Errorf("after re-arm stage = %v, want HEALTHY", got)
	}
}

// TestStatePersists: a new Engine over the same state dir sees the prior check-in.
func TestStatePersists(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	cfg := engine.Config{StateDir: dir, WarnAfter: 10 * time.Minute, FireAfter: 20 * time.Minute}

	e1 := engine.New(cfg, clk)
	if err := e1.Checkin(); err != nil {
		t.Fatal(err)
	}
	e2 := engine.New(cfg, clk)
	if got := e2.Stage(); got != engine.StageHealthy {
		t.Errorf("reloaded engine stage = %v, want HEALTHY", got)
	}
	last, ok := e2.LastCheckin()
	if !ok || !last.Equal(clk.Now()) {
		t.Errorf("LastCheckin not persisted: got %v ok=%v", last, ok)
	}
}

// TestStageUnknownBeforeInit: with no check-in recorded, stage is UNKNOWN.
func TestStageUnknownBeforeInit(t *testing.T) {
	e, _ := newEngine(t)
	if got := e.Stage(); got != engine.StageUnknown {
		t.Errorf("stage before any check-in = %v, want UNKNOWN", got)
	}
}
