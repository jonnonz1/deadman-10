// Command dms is the deadman-10 dead-man switch CLI: encrypt a file or folder to
// a beneficiary, prove you're alive with check-ins, and release the ciphertext if
// you stop. It wires the internal packages (vault, engine, keys, release, config)
// over a real clock and a local state directory.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jonnonz1/deadman-10/internal/config"
	"github.com/jonnonz1/deadman-10/internal/engine"
	"github.com/jonnonz1/deadman-10/internal/release"
)

// realClock supplies wall-clock time to the engine.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// usage prints the command summary.
func usage() {
	fmt.Print(`deadman-10 — dead-man switch

Usage: dms [--dir <home>] <command> [args]

  (--dir / $DMS_HOME set the switch directory; default is the current directory.
   Schedulers should pass an absolute --dir so watch never runs from the wrong
   place and silently does nothing.)

  quickstart           guided setup: keys + seal + arm + recovery card in one step
  init [--auth-checkin] generate keys and arm; --auth-checkin requires signed check-ins
  seal <path>          encrypt a file or folder into the vault
  checkin [--checkin-key F]  record proof of life (signed token if --auth-checkin)
  status [--json]      show stage and time until warn/fire
  watch [--json]       one timer tick: warn or fire if due
  fire --force         manually trigger the fire path (for testing)
  verify [--id PATH]   decrypt the vault to prove recovery works

Durable (no-operator) mode — TIMELOCK.md construction:
  timelock-arm <path> [--unlock-seconds N]
                       seal a file/folder, split the key K-of-N, timelock ONE
                       share to drand; write the beneficiary's K-1 shares
  timelock-recover [--out DIR]
                       reconstruct from the timelocked + beneficiary shares once
                       the drand round has been reached
  timelock-rearm [--unlock-seconds N]
                       push the timelock deadline forward (run on each check-in)
                       so the backstop tracks your liveness; shares stay valid
  recovery-card        print the beneficiary recovery instructions

  notify-test          send a test notification

Thresholds live in config.json. For compressed-timer demos pass --demo, which is
the ONLY way DMS_WARN_AFTER_MINUTES / DMS_FIRE_AFTER_MINUTES take effect (so a
stray env var can't silently shorten the fuse in production).
`)
}

// paths resolves the switch's home directory and config path. Home comes from
// --dir, then DMS_HOME, then the current working directory. Resolving an explicit
// absolute home is what lets a scheduler (cron/launchd/systemd) run `watch`
// reliably regardless of its working directory (threat model C3).
func paths() (root, cfgPath string) {
	if d := flagValue("--dir"); d != "" {
		root = d
	} else if d := os.Getenv("DMS_HOME"); d != "" {
		root = d
	} else {
		root, _ = os.Getwd()
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	return root, filepath.Join(root, "config.json")
}

// ensureInitialized aborts loudly if home holds no armed switch, so a watcher
// pointed at the wrong directory FAILS rather than silently never firing (C3).
func ensureInitialized(root string, cfg *config.Config) {
	if !fileExists(abs(root, cfg.RecipientsFile)) {
		fail(fmt.Errorf("switch not initialized in %s (no %s). Run `dms init` here, "+
			"or point --dir / DMS_HOME at the right directory", root, cfg.RecipientsFile))
	}
}

// loadCfg reads config (or defaults) and applies env overrides.
func loadCfg() (*config.Config, string) {
	root, cfgPath := paths()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fail(err)
	}
	cfg.ApplyEnvOverrides(demoEnabled())
	return cfg, root
}

// abs resolves a config-relative path against root.
func abs(root, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, p)
}

// newEngine builds the engine with a releaser wired from config. The publisher is
// wrapped in Idempotent so a crash-and-retry of a fire never double-publishes to
// an irreversible paid backend (threat model H5); receipts live in the state dir.
func newEngine(cfg *config.Config, root string) *engine.Engine {
	pub := release.NewIdempotent(buildPublisher(cfg, root), abs(root, cfg.StateDir))
	notifier := buildNotifier(cfg)
	rel := release.New(abs(root, cfg.VaultPath), pub, notifier)
	return engine.New(engine.Config{
		StateDir:      abs(root, cfg.StateDir),
		WarnAfter:     cfg.WarnAfter(),
		FireAfter:     cfg.FireAfter(),
		Releaser:      rel,
		CheckinPubKey: cfg.CheckinPubKey,
	}, realClock{})
}

// buildPublisher selects the storage backend from config. Arweave is permanent
// and paid, so dry_run stays the safe default (simulated, no upload); a real
// upload requires dry_run=false AND a configured wallet.
func buildPublisher(cfg *config.Config, root string) release.Publisher {
	switch cfg.Storage {
	case "arweave":
		if cfg.DryRun {
			return release.NewDryRunPublisher("arweave")
		}
		if cfg.ArweaveWallet == "" {
			fail(fmt.Errorf("storage=arweave with dry_run=false requires arweave_wallet (path to a JWK key file) in config.json"))
		}
		gateway := cfg.ArweaveURL
		if gateway == "" {
			gateway = "https://arweave.net"
		}
		return release.NewArweavePublisher(abs(root, cfg.ArweaveWallet), gateway)
	default:
		return release.NewFilePublisher(abs(root, cfg.OutboxDir))
	}
}

// buildNotifier selects the delivery method from config.
func buildNotifier(cfg *config.Config) release.Notifier {
	switch cfg.Notifier {
	case "webhook":
		return release.NewWebhookNotifier(cfg.WebhookURL)
	case "stdout":
		return release.NewStdoutNotifier()
	default:
		return release.NewLocalNotifier()
	}
}

// fail prints an error and exits non-zero.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// demoEnabled reports whether --demo appears anywhere in the args. Demo mode is
// the ONLY way DMS_*_MINUTES env overrides take effect, so a leftover env var
// cannot silently shorten the fuse in production (threat model H8).
func demoEnabled() bool {
	return slices.Contains(os.Args[1:], "--demo")
}

// command returns the subcommand, skipping any leading global flags such as
// `--dir <home>` so `dms --dir X watch` dispatches to "watch".
func command() string {
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		if a == "--dir" {
			i++ // skip its value
			continue
		}
		if strings.HasPrefix(a, "--dir=") || a == "--demo" {
			continue
		}
		return a
	}
	return ""
}

func main() {
	cmd := command()
	if cmd == "" {
		usage()
		os.Exit(2)
	}
	switch cmd {
	case "quickstart":
		cmdQuickstart()
	case "init":
		cmdInit()
	case "seal":
		cmdSeal()
	case "checkin":
		cmdCheckin()
	case "status":
		cmdStatus()
	case "watch":
		cmdWatch()
	case "fire":
		cmdFire()
	case "verify":
		cmdVerify()
	case "timelock-arm":
		cmdTimelockArm()
	case "timelock-recover":
		cmdTimelockRecover()
	case "timelock-rearm":
		cmdTimelockReArm()
	case "recovery-card":
		cmdRecoveryCard()
	case "notify-test":
		cmdNotifyTest()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}
