package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/config"
)

// TestDefaultsAreSafe checks the shipped defaults lean conservative: warn well
// before fire, both measured in weeks not minutes.
func TestDefaultsAreSafe(t *testing.T) {
	c := config.Default()
	if c.WarnAfter() <= 0 || c.FireAfter() <= 0 {
		t.Fatal("durations must be positive")
	}
	if c.WarnAfter() >= c.FireAfter() {
		t.Errorf("warn (%v) must be before fire (%v)", c.WarnAfter(), c.FireAfter())
	}
	if c.FireAfter() < 7*24*time.Hour {
		t.Errorf("default fire window %v is dangerously short; want >= 1 week", c.FireAfter())
	}
}

// TestSaveLoadRoundTrip persists a config and reads it back identically.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := config.Default()
	c.OwnerName = "Alice"
	c.WarnAfterMinutes = 120
	c.FireAfterMinutes = 480
	c.Notifier = "webhook"
	c.WebhookURL = "https://example.test/hook"

	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OwnerName != "Alice" || got.WarnAfterMinutes != 120 || got.FireAfterMinutes != 480 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.WarnAfter() != 120*time.Minute || got.FireAfter() != 480*time.Minute {
		t.Errorf("duration accessors wrong: warn=%v fire=%v", got.WarnAfter(), got.FireAfter())
	}
}

// TestLoadMissingReturnsDefault is a convenience: loading a non-existent path
// yields defaults rather than an error, so a fresh setup just works.
func TestLoadMissingReturnsDefault(t *testing.T) {
	c, err := config.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("expected defaults, got error: %v", err)
	}
	if c.FireAfterMinutes != config.Default().FireAfterMinutes {
		t.Error("missing config should return defaults")
	}
}

// TestEnvOverrideOnlyInDemo: env overrides apply ONLY when demo mode is explicitly
// enabled. A leftover env var with demo off must be ignored, so it can't silently
// arm a hair-trigger fuse (threat model H8).
func TestEnvOverrideOnlyInDemo(t *testing.T) {
	t.Setenv("DMS_WARN_AFTER_MINUTES", "0")
	t.Setenv("DMS_FIRE_AFTER_MINUTES", "0")

	// Demo OFF: env ignored, safe defaults retained.
	off := config.Default()
	off.ApplyEnvOverrides(false)
	if off.FireAfterMinutes != config.Default().FireAfterMinutes {
		t.Errorf("env override leaked with demo OFF: fire=%d", off.FireAfterMinutes)
	}

	// Demo ON: env applies (for compressed-timer demos/tests).
	on := config.Default()
	on.ApplyEnvOverrides(true)
	if on.WarnAfter() != 0 || on.FireAfter() != 0 {
		t.Errorf("env override failed with demo ON: warn=%v fire=%v", on.WarnAfter(), on.FireAfter())
	}
}
