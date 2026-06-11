package release_test

import (
	"testing"

	"github.com/jonnonz1/deadman-10/internal/release"
)

// countingPublisher records how many times the real (expensive) publish happened.
type countingPublisher struct {
	uploads int
	lastID  string
}

func (c *countingPublisher) Publish(ciphertext []byte, publishID string, tags map[string]string) (string, error) {
	c.uploads++
	c.lastID = publishID
	return "loc://" + publishID, nil
}

// TestIdempotentSkipsRepublish is the H5 fix: publishing the same publishID twice
// must perform the real upload only ONCE — protecting an irreversible paid
// backend (Arweave) from a duplicate upload when the fire path retries.
func TestIdempotentSkipsRepublish(t *testing.T) {
	inner := &countingPublisher{}
	p := release.NewIdempotent(inner, t.TempDir())

	loc1, err := p.Publish([]byte("ciphertext"), "fire-abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	loc2, err := p.Publish([]byte("ciphertext"), "fire-abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if inner.uploads != 1 {
		t.Errorf("real upload happened %d times, want 1 (duplicate paid upload!)", inner.uploads)
	}
	if loc1 != loc2 {
		t.Errorf("idempotent publish returned different locators: %q vs %q", loc1, loc2)
	}
}

// TestIdempotentDistinctIDsBothPublish: genuinely different fires (different ids)
// must each publish.
func TestIdempotentDistinctIDsBothPublish(t *testing.T) {
	inner := &countingPublisher{}
	p := release.NewIdempotent(inner, t.TempDir())
	if _, err := p.Publish([]byte("a"), "fire-1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish([]byte("b"), "fire-2", nil); err != nil {
		t.Fatal(err)
	}
	if inner.uploads != 2 {
		t.Errorf("distinct fires uploaded %d times, want 2", inner.uploads)
	}
}

// TestIdempotentSurvivesRestart: a fresh wrapper over the same receipts dir still
// remembers a prior publish (the receipt is durable, not in-memory).
func TestIdempotentSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	inner := &countingPublisher{}
	p1 := release.NewIdempotent(inner, dir)
	if _, err := p1.Publish([]byte("x"), "fire-9", nil); err != nil {
		t.Fatal(err)
	}
	p2 := release.NewIdempotent(inner, dir) // simulate process restart
	if _, err := p2.Publish([]byte("x"), "fire-9", nil); err != nil {
		t.Fatal(err)
	}
	if inner.uploads != 1 {
		t.Errorf("upload happened %d times across restart, want 1", inner.uploads)
	}
}
