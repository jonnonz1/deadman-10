package engine_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/engine"
	"github.com/jonnonz1/deadman-10/internal/release"
)

// crashOncePublisher does the real "upload", then fails the FIRST time (after the
// upload, as a notify/write step would) to simulate a crash mid-fire. It counts
// real uploads so the test can prove no duplicate.
type crashOncePublisher struct {
	uploads    int
	failedOnce bool
}

func (p *crashOncePublisher) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	p.uploads++
	return "loc://" + publishID, nil
}

// releaserThatCrashesAfterPublish publishes (counting the upload) then returns an
// error on the first call only, mimicking a failure after the irreversible upload
// but before `fired` is written.
type releaserThatCrashesAfterPublish struct {
	pub      *crashOncePublisher
	idem     *release.Idempotent
	failNext bool
}

func (r *releaserThatCrashesAfterPublish) Release(publishID string, elapsed time.Duration) error {
	if _, err := r.idem.Publish([]byte("ciphertext"), publishID, nil); err != nil {
		return err
	}
	if r.failNext {
		r.failNext = false
		return errors.New("simulated crash after publish, before fired write")
	}
	return nil
}

// TestFireRetryDoesNotDoublePublish is the H5 regression test: when a fire
// publishes successfully but then the tick fails before `fired` is written, the
// next watch tick must NOT publish again — the irreversible upload happens once.
func TestFireRetryDoesNotDoublePublish(t *testing.T) {
	dir := t.TempDir()
	clk := &fixedClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	pub := &crashOncePublisher{}
	rel := &releaserThatCrashesAfterPublish{
		pub:      pub,
		idem:     release.NewIdempotent(pub, dir),
		failNext: true,
	}
	e := engine.New(engine.Config{
		StateDir:  dir,
		WarnAfter: 1 * time.Minute,
		FireAfter: 2 * time.Minute,
		Releaser:  rel,
	}, clk)

	if err := e.Checkin(); err != nil {
		t.Fatal(err)
	}
	clk.advance(5 * time.Minute) // past fire

	// First tick: publishes, then "crashes" -> error, fired NOT written.
	if _, err := e.Watch(); err == nil {
		t.Fatal("expected first watch to error (simulated crash)")
	}
	if e.Fired() {
		t.Fatal("fired should not be set after a crashed fire")
	}

	// Second tick: retries. Must complete WITHOUT a second real upload.
	r2, err := e.Watch()
	if err != nil {
		t.Fatalf("retry watch errored: %v", err)
	}
	if r2.Action != engine.ActionFired {
		t.Errorf("retry action = %v, want fired", r2.Action)
	}
	if pub.uploads != 1 {
		t.Errorf("real upload happened %d times across crash+retry, want 1 (H5!)", pub.uploads)
	}
	if !e.Fired() {
		t.Error("fired should be set after successful retry")
	}
}
