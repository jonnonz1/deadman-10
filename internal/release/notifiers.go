package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

// StdoutNotifier prints events to stdout. The simplest, always-available option.
type StdoutNotifier struct{}

// NewStdoutNotifier returns a stdout notifier.
func NewStdoutNotifier() *StdoutNotifier { return &StdoutNotifier{} }

// Notify prints a timestamped line and never fails.
func (n *StdoutNotifier) Notify(level, subject, body string) error {
	fmt.Printf("%s [%s] %s :: %s\n", time.Now().UTC().Format(time.RFC3339), level, subject, body)
	return nil
}

// LocalNotifier shows a desktop notification on macOS (osascript), falling back
// to stdout elsewhere.
type LocalNotifier struct{ fallback *StdoutNotifier }

// NewLocalNotifier returns a desktop notifier.
func NewLocalNotifier() *LocalNotifier { return &LocalNotifier{fallback: NewStdoutNotifier()} }

// Notify posts a desktop notification, or prints if that is unavailable.
func (n *LocalNotifier) Notify(level, subject, body string) error {
	_ = n.fallback.Notify(level, subject, body)
	if runtime.GOOS == "darwin" {
		script := fmt.Sprintf("display notification %q with title %q", body, "DMS: "+subject)
		_ = exec.Command("osascript", "-e", script).Run()
	}
	return nil
}

// WebhookNotifier POSTs a Slack-compatible JSON payload to a webhook URL. This is
// the no-human-present delivery path.
type WebhookNotifier struct {
	url      string
	fallback *StdoutNotifier
}

// NewWebhookNotifier returns a webhook notifier for url.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{url: url, fallback: NewStdoutNotifier()}
}

// webhookAttempts is how many times Notify tries before giving up.
const webhookAttempts = 3

// Notify sends the message to the webhook (retrying on transport error or non-2xx)
// and also prints it locally. A non-2xx response is treated as failure so the WARN
// brake does not silently fail open (threat model B5). The returned error is for
// the caller to LOG loudly — firing must never be gated on notify success, or a
// dead webhook becomes a suppression vector.
func (n *WebhookNotifier) Notify(level, subject, body string) error {
	_ = n.fallback.Notify(level, subject, body)
	if n.url == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"text": fmt.Sprintf("*%s*\n%s", subject, body)})

	var lastErr error
	for attempt := 0; attempt < webhookAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond) // linear backoff
		}
		resp, err := http.Post(n.url, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", webhookAttempts, lastErr)
}
