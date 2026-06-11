package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonnonz1/deadman-10/internal/config"
	"github.com/jonnonz1/deadman-10/internal/keys"
	"github.com/jonnonz1/deadman-10/internal/release"
	"github.com/jonnonz1/deadman-10/internal/signing"
	"github.com/jonnonz1/deadman-10/internal/vault"
)

// cmdInit generates the switch's keys and arms it. The host keeps ONLY public
// keys, so a host compromise never yields plaintext (threat model H1):
//   - beneficiary encryption key (age): the vault is encrypted to its PUBLIC half;
//     the private half is printed once for the beneficiary to store offline.
//   - owner signing key (ed25519): used at `seal` time to sign the vault so a
//     forged vault is detectable (H3). Printed once; the host keeps only the
//     public half. The owner is NOT an encryption recipient — recovery is via the
//     beneficiary key alone.
func cmdInit() {
	dev := hasFlag("--dev")
	force := hasFlag("--force")
	cfg, root := loadCfg()

	keysDir := abs(root, cfg.KeysDir)
	recFile := abs(root, cfg.RecipientsFile)
	vaultPath := abs(root, cfg.VaultPath)

	if fileExists(recFile) && !force {
		fail(fmt.Errorf("already initialized (use --force to regenerate keys)"))
	}
	if force && fileExists(vaultPath) {
		fail(fmt.Errorf("refusing to rotate keys: %s exists and is encrypted to the current keys; "+
			"regenerating would make it permanently unopenable. Move/delete the vault first", vaultPath))
	}
	must(os.MkdirAll(keysDir, 0o700))
	must(os.MkdirAll(abs(root, cfg.StateDir), 0o700))

	ben, err := keys.Generate()
	must(err)
	ownerSign, err := signing.Generate()
	must(err)

	// Optional authenticated check-in (H5): a check-in key whose PUBLIC half lives
	// on the host; check-ins must then be signed tokens.
	authCheckin := hasFlag("--auth-checkin")
	var checkinKP signing.Keypair
	if authCheckin {
		checkinKP, err = signing.Generate()
		must(err)
		cfg.CheckinPubKey = checkinKP.Public
		must(os.WriteFile(filepath.Join(keysDir, "checkin.pub"), []byte(checkinKP.Public+"\n"), 0o600))
		if dev {
			must(os.WriteFile(filepath.Join(keysDir, "checkin.key"), []byte(checkinKP.Private+"\n"), 0o600))
		}
	}

	// Host keeps only public material + the recipients file (beneficiary only).
	must(os.WriteFile(filepath.Join(keysDir, "beneficiary.pub"), []byte(ben.Public+"\n"), 0o600))
	must(os.WriteFile(filepath.Join(keysDir, "owner-sign.pub"), []byte(ownerSign.Public+"\n"), 0o600))
	must(os.WriteFile(recFile, []byte(ben.Public+"\n"), 0o600))
	if dev {
		// Dev convenience only: retain private keys on the host for local testing.
		must(os.WriteFile(filepath.Join(keysDir, "beneficiary.key"), []byte(ben.Private+"\n"), 0o600))
		must(os.WriteFile(filepath.Join(keysDir, "owner-sign.key"), []byte(ownerSign.Private+"\n"), 0o600))
	}

	must(cfg.Save(filepath.Join(root, "config.json")))
	e := newEngine(cfg, root)
	if authCheckin {
		tok, err := signing.SignToken(checkinKP.Private, time.Now())
		must(err)
		must(e.AuthCheckin(tok))
	} else {
		must(e.Checkin())
	}

	fmt.Println("deadman-10 initialized. The host holds only PUBLIC keys.")
	fmt.Printf("  beneficiary public key : %s\n", ben.Public)
	fmt.Printf("  owner signing public   : %s\n", ownerSign.Public)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("SAVE THESE TWO PRIVATE KEYS OFFLINE NOW — they are not stored on the host.")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("BENEFICIARY PRIVATE KEY (give to your beneficiary; opens the vault):")
	fmt.Println(ben.Private)
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("OWNER SIGNING KEY (keep yourself; needed to `dms seal`):")
	fmt.Println(ownerSign.Private)
	if authCheckin {
		fmt.Println(strings.Repeat("-", 70))
		fmt.Println("CHECK-IN KEY (keep yourself; needed for every `dms checkin`):")
		fmt.Println(checkinKP.Private)
	}
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Pass the owner signing key to seal:  dms seal <path> --owner-sign-key <file>")
	if authCheckin {
		fmt.Println("This switch requires SIGNED check-ins:  dms checkin --checkin-key <file>")
	}
	if dev {
		fmt.Println("[dev] private keys also saved under keys/ for local testing only.")
	}
}

// cmdSeal encrypts a file or folder into the vault for the beneficiary, then
// signs the ciphertext with the owner signing key so the beneficiary can detect a
// forged or substituted vault (H3). The signing key is supplied at seal time
// (--owner-sign-key) and never stored on the host outside --dev.
func cmdSeal() {
	if len(os.Args) < 3 {
		fail(fmt.Errorf("usage: dms seal <path> [--owner-sign-key <file>]"))
	}
	src := os.Args[2]
	cfg, root := loadCfg()
	recFile := abs(root, cfg.RecipientsFile)
	if !fileExists(recFile) {
		fail(fmt.Errorf("run `dms init` first"))
	}
	recipients := readLines(recFile)
	out := abs(root, cfg.VaultPath)
	n, err := vault.Seal(src, recipients, out)
	must(err)
	fmt.Printf("sealed %s -> %s (%d bytes of ciphertext)\n", src, out, n)

	signKey := resolveSigningKey(root, cfg)
	if signKey == "" {
		fmt.Println("warning: no owner signing key supplied; vault is UNSIGNED and a")
		fmt.Println("substituted vault would be undetectable. Re-seal with --owner-sign-key.")
		return
	}
	ciphertext, err := os.ReadFile(out)
	must(err)
	sig, err := signing.Sign(signKey, ciphertext)
	must(err)
	must(os.WriteFile(out+".sig", sig, 0o600))
	fmt.Printf("signed -> %s.sig (owner provenance; beneficiary can verify)\n", out)
}

// resolveSigningKey returns the owner signing private key from --owner-sign-key,
// or the dev-mode on-host key, or "" if none is available.
func resolveSigningKey(root string, cfg *config.Config) string {
	if p := flagValue("--owner-sign-key"); p != "" {
		return strings.TrimSpace(readFile(p))
	}
	devKey := filepath.Join(abs(root, cfg.KeysDir), "owner-sign.key")
	if fileExists(devKey) {
		return strings.TrimSpace(readFile(devKey))
	}
	return ""
}

// cmdCheckin records proof of life. If the switch requires authenticated
// check-ins (H5), it signs a token with the owner check-in key (--checkin-key,
// or the dev on-host key) and submits it; otherwise it does a plain check-in.
func cmdCheckin() {
	cfg, root := loadCfg()
	ensureInitialized(root, cfg)
	e := newEngine(cfg, root)
	if cfg.CheckinPubKey != "" {
		key := resolveCheckinKey(root, cfg)
		if key == "" {
			fail(fmt.Errorf("this switch requires a signed check-in: pass --checkin-key <file>"))
		}
		tok, err := signing.SignToken(key, time.Now())
		must(err)
		must(e.AuthCheckin(tok))
	} else {
		must(e.Checkin())
	}
	fmt.Printf("checked in. warns after %v, fires after %v without check-in\n",
		cfg.WarnAfter(), cfg.FireAfter())
}

// resolveCheckinKey returns the owner check-in private key from --checkin-key, or
// the dev on-host key, or "".
func resolveCheckinKey(root string, cfg *config.Config) string {
	if p := flagValue("--checkin-key"); p != "" {
		return strings.TrimSpace(readFile(p))
	}
	devKey := filepath.Join(abs(root, cfg.KeysDir), "checkin.key")
	if fileExists(devKey) {
		return strings.TrimSpace(readFile(devKey))
	}
	return ""
}

// cmdStatus prints the current stage and deadlines.
func cmdStatus() {
	cfg, root := loadCfg()
	ensureInitialized(root, cfg)
	e := newEngine(cfg, root)
	last, ok := e.LastCheckin()
	snap := map[string]any{
		"stage":              string(e.Stage()),
		"fired":              e.Fired(),
		"warn_after_minutes": cfg.WarnAfterMinutes,
		"fire_after_minutes": cfg.FireAfterMinutes,
		"notifier":           cfg.Notifier,
		"storage":            cfg.Storage,
	}
	if ok {
		snap["last_checkin"] = last.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if hasFlag("--json") {
		b, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("stage         : %s\n", e.Stage())
	if ok {
		fmt.Printf("last check-in : %s\n", last.UTC().Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Printf("fired         : %v\n", e.Fired())
	fmt.Printf("warn after    : %v\n", cfg.WarnAfter())
	fmt.Printf("fire after    : %v\n", cfg.FireAfter())
}

// cmdWatch runs one timer tick.
func cmdWatch() {
	cfg, root := loadCfg()
	ensureInitialized(root, cfg) // C3: fail loud, never silently no-op on a misconfigured home
	e := newEngine(cfg, root)
	res, err := e.Watch()
	must(err)
	if hasFlag("--json") {
		b, _ := json.Marshal(map[string]any{
			"stage":   string(res.Stage),
			"action":  string(res.Action),
			"elapsed": res.Elapsed.String(),
		})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("[watch] stage=%s action=%s elapsed=%v\n", res.Stage, res.Action, res.Elapsed.Round(1e9))
}

// cmdFire manually triggers the fire path for testing.
func cmdFire() {
	if !hasFlag("--force") {
		fail(fmt.Errorf("refusing to fire without --force"))
	}
	cfg, root := loadCfg()
	// Force a fire by directly invoking the releaser. Wrap in Idempotent so even a
	// forced re-fire of the same check-in does not double-publish (H5).
	pub := release.NewIdempotent(buildPublisher(cfg, root), abs(root, cfg.StateDir))
	notifier := buildNotifier(cfg)
	rel := releaserFor(cfg, root, pub, notifier)
	must(rel.Release("fire-forced", 0))
	fmt.Println("fired (forced).")
}

// cmdVerify decrypts the vault with the beneficiary identity, first checking the
// owner's provenance signature so a forged vault is rejected before decryption.
func cmdVerify() {
	cfg, root := loadCfg()
	idPath := flagValue("--id")
	if idPath == "" {
		idPath = filepath.Join(abs(root, cfg.KeysDir), "beneficiary.key")
	}
	if !fileExists(idPath) {
		fail(fmt.Errorf("identity not found: %s (pass --id, or run `init --dev`)", idPath))
	}
	checkProvenance(root, cfg, abs(root, cfg.VaultPath))
	identity := strings.TrimSpace(readFile(idPath))
	out := flagValue("--out")
	if out == "" {
		// Default: prove recovery without persisting plaintext — extract to a
		// temp dir, list it, then remove it immediately.
		dest, err := os.MkdirTemp("", "dms-verify-")
		must(err)
		defer os.RemoveAll(dest)
		must(vault.Open(abs(root, cfg.VaultPath), identity, dest))
		fmt.Println("decrypted OK (recovery proven; plaintext not persisted)")
		fmt.Println("contents:")
		printTree(dest)
		return
	}
	// Explicit --out: the beneficiary actually wants the recovered files on disk.
	must(vault.Open(abs(root, cfg.VaultPath), identity, out))
	fmt.Printf("decrypted OK -> %s\n", out)
	printTree(out)
}

// checkProvenance verifies the vault's owner signature (vault.age.sig) against
// the owner signing public key. It aborts on a present-but-invalid signature
// (forgery), warns loudly if either the signature or the public key is missing,
// and is silent on success. An explicit --owner-sign-pub overrides the on-host
// public key (e.g. the beneficiary supplies the value from their recovery card).
func checkProvenance(root string, cfg *config.Config, vaultPath string) {
	sigPath := vaultPath + ".sig"
	pub := flagValue("--owner-sign-pub")
	if pub == "" {
		pubFile := filepath.Join(abs(root, cfg.KeysDir), "owner-sign.pub")
		if fileExists(pubFile) {
			pub = strings.TrimSpace(readFile(pubFile))
		}
	}
	if !fileExists(sigPath) || pub == "" {
		fmt.Println("warning: no provenance signature checked — cannot confirm this")
		fmt.Println("vault is the owner's (was it sealed with --owner-sign-key?).")
		return
	}
	sig, err := os.ReadFile(sigPath)
	must(err)
	ciphertext, err := os.ReadFile(vaultPath)
	must(err)
	if err := signing.Verify(pub, ciphertext, sig); err != nil {
		fail(fmt.Errorf("PROVENANCE CHECK FAILED: %w — refusing to treat this vault as the owner's", err))
	}
	fmt.Println("provenance OK (vault signed by the owner signing key).")
}

// printTree lists the regular files under root, relative to it.
func printTree(root string) {
	_ = filepath.Walk(root, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			rel, _ := filepath.Rel(root, p)
			fmt.Printf("  %s\n", rel)
		}
		return nil
	})
}

// cmdNotifyTest sends a test notification.
func cmdNotifyTest() {
	cfg, _ := loadCfg()
	n := buildNotifier(cfg)
	must(n.Notify("TEST", "deadman-10 test", "If you can read this, notifications work."))
}
