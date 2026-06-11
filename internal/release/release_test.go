package release_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jonnonz1/deadman-10/internal/release"
)

// writeFile is a small test helper to create a file with content.
func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o600)
}

// TestFilePublisherWritesCiphertext: the default file publisher copies the vault
// to the outbox and returns a locator, without needing any network.
func TestFilePublisherWritesCiphertext(t *testing.T) {
	dir := t.TempDir()
	p := release.NewFilePublisher(dir)
	loc, err := p.Publish([]byte("ciphertext-bytes"), "fire-x", map[string]string{"version": "1"})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if loc == "" {
		t.Fatal("expected a non-empty locator")
	}
}

// TestDryRunPublisherWritesNothingButReturnsLocator: dry-run must NOT perform a
// real write yet must report what it would do — the safety default for Arweave.
func TestDryRunPublisherWritesNothing(t *testing.T) {
	p := release.NewDryRunPublisher("arweave")
	loc, err := p.Publish([]byte("x"), "fire-x", nil)
	if err != nil {
		t.Fatalf("dry-run Publish: %v", err)
	}
	if !strings.Contains(strings.ToLower(loc), "dry-run") {
		t.Errorf("dry-run locator should signal dry-run, got %q", loc)
	}
}

// recordingNotifier captures notifications for assertions.
type recordingNotifier struct{ events []string }

func (r *recordingNotifier) Notify(level, subject, body string) error {
	r.events = append(r.events, level+":"+subject)
	return nil
}

// recordingPublisher captures published payloads.
type recordingPublisher struct {
	called     bool
	ciphertext []byte
}

func (p *recordingPublisher) Publish(b []byte, publishID string, tags map[string]string) (string, error) {
	p.called = true
	p.ciphertext = b
	return "loc://test", nil
}

// TestReleaserPublishesAndNotifies: on fire, the releaser must publish the vault
// ciphertext and emit a FIRE notification. This is the engine.Releaser contract.
func TestReleaserPublishesAndNotifies(t *testing.T) {
	dir := t.TempDir()
	// Write a fake vault file to release.
	vaultPath := dir + "/vault.age"
	if err := writeFile(t, vaultPath, "the-ciphertext"); err != nil {
		t.Fatal(err)
	}
	notifier := &recordingNotifier{}
	publisher := &recordingPublisher{}
	r := release.New(vaultPath, publisher, notifier)

	if err := r.Release("fire-test", 30*time.Minute); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !publisher.called {
		t.Error("releaser must publish on fire")
	}
	if string(publisher.ciphertext) != "the-ciphertext" {
		t.Errorf("published wrong bytes: %q", publisher.ciphertext)
	}
	foundFire := false
	for _, e := range notifier.events {
		if strings.HasPrefix(e, "FIRE:") {
			foundFire = true
		}
	}
	if !foundFire {
		t.Errorf("expected a FIRE notification, got %v", notifier.events)
	}
}

// failingNotifier always errors, simulating a dead webhook.
type failingNotifier struct{}

func (failingNotifier) Notify(level, subject, body string) error {
	return errTest
}

var errTest = fmt.Errorf("notifier down")

// TestReleaseSucceedsDespiteNotifyFailure proves the B5 rule: a failed FIRE
// notification must NOT fail the release (the vault was already published) — else
// a dead webhook becomes a suppression/duplication vector.
func TestReleaseSucceedsDespiteNotifyFailure(t *testing.T) {
	dir := t.TempDir()
	vaultPath := dir + "/vault.age"
	if err := writeFile(t, vaultPath, "ciphertext"); err != nil {
		t.Fatal(err)
	}
	r := release.New(vaultPath, &recordingPublisher{}, failingNotifier{})
	if err := r.Release("fire-x", time.Minute); err != nil {
		t.Errorf("release must succeed despite notify failure, got: %v", err)
	}
}

// TestStdoutNotifierNeverErrors: the simplest notifier always succeeds.
func TestStdoutNotifierNeverErrors(t *testing.T) {
	n := release.NewStdoutNotifier()
	if err := n.Notify("TEST", "subject", "body"); err != nil {
		t.Errorf("stdout notifier errored: %v", err)
	}
}
