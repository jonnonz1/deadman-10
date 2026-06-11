package release_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jonnonz1/deadman-10/internal/release"
)

// TestWebhookNon2xxIsError: a webhook returning 500 must surface as an error so
// the WARN brake is not silently failing open (threat model B5).
func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := release.NewWebhookNotifier(srv.URL)
	if err := n.Notify("WARN", "s", "b"); err == nil {
		t.Fatal("expected error on HTTP 500, got nil (brake fails open)")
	}
}

// TestWebhookRetriesThenSucceeds: a webhook that fails twice then returns 200 must
// be retried and ultimately succeed.
func TestWebhookRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := release.NewWebhookNotifier(srv.URL)
	if err := n.Notify("WARN", "s", "b"); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if calls.Load() < 3 {
		t.Errorf("expected >=3 attempts (2 fails + 1 success), got %d", calls.Load())
	}
}

// TestWebhook2xxSucceeds: a healthy webhook succeeds on the first try.
func TestWebhook2xxSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := release.NewWebhookNotifier(srv.URL)
	if err := n.Notify("WARN", "s", "b"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("healthy webhook should be hit once, got %d", calls.Load())
	}
}
