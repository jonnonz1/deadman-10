// Package config holds the switch's persisted settings: identity, thresholds,
// paths, custody (Shamir K-of-N), notifier, and storage. Durations are stored as
// minutes for human-editability and exposed as time.Duration via accessors.
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

// Config is the on-disk settings for one switch.
type Config struct {
	OwnerName        string `json:"owner_name"`
	WarnAfterMinutes int    `json:"warn_after_minutes"`
	FireAfterMinutes int    `json:"fire_after_minutes"`

	VaultPath      string `json:"vault_path"`
	RecipientsFile string `json:"recipients_file"`
	KeysDir        string `json:"keys_dir"`
	StateDir       string `json:"state_dir"`
	OutboxDir      string `json:"outbox_dir"`

	// Custody: split the vault key into N Shamir shares, K to reconstruct.
	ShamirN int `json:"shamir_n"`
	ShamirK int `json:"shamir_k"`

	Notifier   string `json:"notifier"` // local | webhook | stdout
	WebhookURL string `json:"webhook_url"`

	// CheckinPubKey, when set, requires authenticated (signed) check-ins (H5).
	CheckinPubKey string `json:"checkin_pub_key"`

	// Storage: where the released ciphertext is published.
	Storage       string `json:"storage"`        // file | arweave
	ArweaveURL    string `json:"arweave_url"`    // gateway URL or arlocal for devnet
	ArweaveWallet string `json:"arweave_wallet"` // path to the JWK key file for uploads
	DryRun        bool   `json:"dry_run"`        // never write to a real network when true
}

// Default returns conservative settings: warn after 7 days, fire after 21 days.
func Default() *Config {
	return &Config{
		OwnerName:        "Owner",
		WarnAfterMinutes: 7 * 24 * 60,
		FireAfterMinutes: 21 * 24 * 60,
		VaultPath:        "vault.age",
		RecipientsFile:   "keys/recipients.txt",
		KeysDir:          "keys",
		StateDir:         "state",
		OutboxDir:        "outbox",
		ShamirN:          3,
		ShamirK:          2,
		Notifier:         "local",
		Storage:          "file",
		DryRun:           true,
	}
}

// WarnAfter returns the warn threshold as a duration.
func (c *Config) WarnAfter() time.Duration {
	return time.Duration(c.WarnAfterMinutes) * time.Minute
}

// FireAfter returns the fire threshold as a duration.
func (c *Config) FireAfter() time.Duration {
	return time.Duration(c.FireAfterMinutes) * time.Minute
}

// Load reads a config file, returning defaults if the file does not exist.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the config as indented JSON.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// ApplyEnvOverrides lets the compressed-timer demo override thresholds via
// DMS_WARN_AFTER_MINUTES / DMS_FIRE_AFTER_MINUTES, but ONLY when demo mode is
// explicitly enabled (the --demo flag). This prevents a leftover/injected env var
// from silently shortening the fuse in production (threat model H8). It does not
// defend against a deliberate local attacker (who can edit config.json directly) —
// it removes the accidental-hair-trigger footgun, nothing more.
func (c *Config) ApplyEnvOverrides(demo bool) {
	if !demo {
		return
	}
	if v, ok := os.LookupEnv("DMS_WARN_AFTER_MINUTES"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.WarnAfterMinutes = n
		}
	}
	if v, ok := os.LookupEnv("DMS_FIRE_AFTER_MINUTES"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.FireAfterMinutes = n
		}
	}
}
