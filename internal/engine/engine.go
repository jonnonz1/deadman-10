// Package engine is the dead-man switch timer: it records proof-of-life
// check-ins, computes the current stage from elapsed time, and on a watch tick
// warns or fires. All time comes from an injected Clock and all side effects of
// firing go through an injected Releaser, so the core logic is pure and testable.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jonnonz1/deadman-10/internal/signing"
)

// Stage is the switch's position in its lifecycle.
type Stage string

const (
	StageUnknown Stage = "UNKNOWN" // no check-in recorded yet
	StageHealthy Stage = "HEALTHY" // within the warn window
	StageWarn    Stage = "WARN"    // past warn, before fire
	StageFire    Stage = "FIRE"    // past the fire deadline
)

// Action is what a watch tick did.
type Action string

const (
	ActionNone   Action = "none"
	ActionWarned Action = "warned"
	ActionFired  Action = "fired"
)

// Clock supplies the current time; tests inject a controllable one.
type Clock interface {
	Now() time.Time
}

// Releaser performs the side effect of firing (e.g. publish ciphertext, notify).
// It is optional; a nil Releaser makes firing a pure state transition. publishID
// is a stable idempotency key for this fire event (derived from the check-in the
// fire is based on), so a crash-and-retry does not double-publish.
type Releaser interface {
	Release(publishID string, elapsed time.Duration) error
}

// Config holds the switch thresholds and where state is persisted.
type Config struct {
	StateDir  string
	WarnAfter time.Duration
	FireAfter time.Duration
	Releaser  Releaser

	// CheckinPubKey, when set, requires check-ins to be signed tokens verifiable
	// against this owner public key (threat model H5). Plain Checkin is then
	// refused, so a process without the owner key cannot fake proof of life.
	CheckinPubKey string
}

// Engine is a single dead-man switch over a state directory.
type Engine struct {
	cfg Config
	clk Clock
}

// New constructs an Engine. The state directory is created on first write.
func New(cfg Config, clk Clock) *Engine {
	return &Engine{cfg: cfg, clk: clk}
}

// Result reports the outcome of a watch tick.
type Result struct {
	Stage   Stage
	Action  Action
	Elapsed time.Duration
}

func (e *Engine) path(name string) string {
	return filepath.Join(e.cfg.StateDir, name)
}

// Checkin records an UNAUTHENTICATED proof of life. It is refused when a check-in
// public key is configured (use AuthCheckin instead), so authentication cannot be
// bypassed by calling the plain path.
func (e *Engine) Checkin() error {
	if e.cfg.CheckinPubKey != "" {
		return fmt.Errorf("this switch requires a signed check-in token; use an authenticated check-in")
	}
	return e.recordCheckin(e.clk.Now().UTC())
}

// AuthCheckin records proof of life from a signed token (threat model H5). The
// token must verify against the configured check-in public key and assert a time
// at or after the monotonic floor (so a replayed older token is rejected).
func (e *Engine) AuthCheckin(token []byte) error {
	if e.cfg.CheckinPubKey == "" {
		return fmt.Errorf("no check-in key configured for this switch")
	}
	when, err := signing.VerifyToken(e.cfg.CheckinPubKey, token)
	if err != nil {
		return fmt.Errorf("check-in token: %w", err)
	}
	if floor, ok := e.readTime("checkin_floor"); ok && when.Before(floor) {
		return fmt.Errorf("check-in token is older than the last accepted check-in (replay?)")
	}
	// Record using the engine clock so a future-dated token can't extend life
	// (the token authenticates WHO, the clock decides WHEN it counts from).
	return e.recordCheckin(e.clk.Now().UTC())
}

// recordCheckin stamps proof of life at `now`, advances the monotonic floor, and
// clears warn/fired state, re-arming the switch.
func (e *Engine) recordCheckin(now time.Time) error {
	if err := os.MkdirAll(e.cfg.StateDir, 0o700); err != nil {
		return err
	}
	stamp := now.Format(time.RFC3339)
	if err := os.WriteFile(e.path("last_checkin"), []byte(stamp), 0o600); err != nil {
		return err
	}
	// Advance the monotonic floor to the latest check-in ever seen. The floor lets
	// the engine detect a rolled-BACK last_checkin (which would age the switch
	// toward a premature fire) and ignore it. NOTE (threat model H4): on a
	// single-binary host the floor is not a defence against a same-uid attacker who
	// can rewrite both files — it guards against clock skew, accidental corruption,
	// and naive rollback, not a determined local adversary.
	if floor, ok := e.readTime("checkin_floor"); !ok || now.After(floor) {
		_ = os.WriteFile(e.path("checkin_floor"), []byte(stamp), 0o600)
	}
	_ = os.Remove(e.path("fired"))
	_ = os.Remove(e.path("firing"))
	_ = os.WriteFile(e.path("nags"), []byte("0"), 0o600)
	return nil
}

// readTime parses an RFC3339 timestamp from a state file.
func (e *Engine) readTime(name string) (time.Time, bool) {
	b, err := os.ReadFile(e.path(name))
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// LastCheckin returns the recorded check-in time, if any.
func (e *Engine) LastCheckin() (time.Time, bool) {
	return e.readTime("last_checkin")
}

// effectiveCheckin returns the time the switch should age from: the LATER of the
// recorded check-in and the monotonic floor. Using the later of the two means a
// rolled-back last_checkin cannot bring the fire deadline closer.
func (e *Engine) effectiveCheckin() (time.Time, bool) {
	last, ok := e.LastCheckin()
	if !ok {
		return time.Time{}, false
	}
	if floor, ok := e.readTime("checkin_floor"); ok && floor.After(last) {
		return floor, true
	}
	return last, true
}

// elapsed returns time since the effective check-in, clamped to >= 0 so a
// future-dated stamp cannot manufacture extra life.
func (e *Engine) elapsed() (time.Duration, bool) {
	eff, ok := e.effectiveCheckin()
	if !ok {
		return 0, false
	}
	d := e.clk.Now().Sub(eff)
	if d < 0 {
		d = 0
	}
	return d, true
}

// Stage computes the current lifecycle stage from elapsed time.
func (e *Engine) Stage() Stage {
	d, ok := e.elapsed()
	if !ok {
		return StageUnknown
	}
	switch {
	case d >= e.cfg.FireAfter:
		return StageFire
	case d >= e.cfg.WarnAfter:
		return StageWarn
	default:
		return StageHealthy
	}
}

// Fired reports whether the switch has already fired (and not been re-armed).
func (e *Engine) Fired() bool {
	_, err := os.Stat(e.path("fired"))
	return err == nil
}

// Nags returns the count of warnings emitted in the current warn window.
func (e *Engine) Nags() int {
	b, err := os.ReadFile(e.path("nags"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// Watch is one timer tick: it warns in the warn window or fires once past the
// deadline. Firing is idempotent — a second tick after firing does nothing.
func (e *Engine) Watch() (Result, error) {
	stage := e.Stage()
	d, _ := e.elapsed()
	res := Result{Stage: stage, Action: ActionNone, Elapsed: d}

	switch stage {
	case StageFire:
		if e.Fired() {
			return res, nil
		}
		if err := os.MkdirAll(e.cfg.StateDir, 0o700); err != nil {
			return res, err
		}
		// publishID is stable for this fire (anchored to the check-in it is based
		// on), so a crash-and-retry reuses it and the Idempotent publisher never
		// double-publishes to an irreversible paid backend (threat model H5).
		publishID := e.firePublishID()
		// Record fire intent BEFORE releasing, so a partial fire is recoverable
		// rather than silently re-attempted from scratch.
		if err := os.WriteFile(e.path("firing"), []byte(publishID), 0o600); err != nil {
			return res, err
		}
		if e.cfg.Releaser != nil {
			if err := e.cfg.Releaser.Release(publishID, d); err != nil {
				return res, err
			}
		}
		stamp := e.clk.Now().UTC().Format(time.RFC3339)
		if err := os.WriteFile(e.path("fired"), []byte(stamp), 0o600); err != nil {
			return res, err
		}
		res.Action = ActionFired
	case StageWarn:
		if err := e.bumpNag(); err != nil {
			return res, err
		}
		res.Action = ActionWarned
	}
	return res, nil
}

// firePublishID derives a stable idempotency key for the current fire, anchored
// to the check-in the fire is based on. Retrying the same fire yields the same id
// (so no double-publish); a genuine re-arm changes last_checkin and thus the id.
func (e *Engine) firePublishID() string {
	last, ok := e.LastCheckin()
	if !ok {
		return "fire-unknown"
	}
	return "fire-" + last.UTC().Format("20060102T150405Z")
}

// bumpNag increments the escalating warning counter.
func (e *Engine) bumpNag() error {
	if err := os.MkdirAll(e.cfg.StateDir, 0o700); err != nil {
		return err
	}
	n := e.Nags() + 1
	return os.WriteFile(e.path("nags"), []byte(strconv.Itoa(n)), 0o600)
}
