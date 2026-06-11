package main_test

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildDMS compiles the dms binary into a temp dir once per test run.
func buildDMS(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "dms")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build dms: %v\n%s", err, out)
	}
	return bin
}

// run executes the binary in dir with env overrides and returns combined output.
func run(t *testing.T, bin, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dms %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestCLIFullLifecycle drives the real binary through the whole switch: init,
// seal a folder, fire via compressed timers, decrypt as beneficiary, re-arm.
func TestCLIFullLifecycle(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()

	// A nested secret folder.
	must(t, os.MkdirAll(filepath.Join(dir, "secrets", "sub"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "a.txt"), []byte("alpha"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "sub", "b.txt"), []byte("bravo"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))

	run(t, bin, dir, nil, "init", "--dev")
	if !fileExists(filepath.Join(dir, "keys", "recipients.txt")) {
		t.Fatal("init did not create recipients file")
	}

	sealOut := run(t, bin, dir, nil, "seal", "secrets")
	if !strings.Contains(sealOut, "ciphertext") {
		t.Errorf("seal output unexpected: %s", sealOut)
	}

	// Healthy right after init.
	if st := run(t, bin, dir, nil, "status", "--json"); !strings.Contains(st, `"stage": "HEALTHY"`) {
		t.Errorf("expected HEALTHY, got %s", st)
	}

	// Fire via compressed timers.
	fireEnv := []string{"DMS_WARN_AFTER_MINUTES=0", "DMS_FIRE_AFTER_MINUTES=0"}
	fireOut := run(t, bin, dir, fireEnv, "--demo", "watch")
	if !strings.Contains(fireOut, "action=fired") {
		t.Errorf("expected fire, got %s", fireOut)
	}
	if !fileExists(filepath.Join(dir, "outbox", "vault.age")) {
		t.Fatal("fire did not release ciphertext to outbox")
	}

	// Beneficiary decrypts.
	verifyOut := run(t, bin, dir, nil, "verify")
	if !strings.Contains(verifyOut, "a.txt") || !strings.Contains(verifyOut, "b.txt") {
		t.Errorf("verify did not recover folder tree: %s", verifyOut)
	}

	// Re-arm clears fired.
	run(t, bin, dir, nil, "checkin")
	if st := run(t, bin, dir, nil, "status", "--json"); !strings.Contains(st, `"fired": false`) {
		t.Errorf("checkin did not clear fired: %s", st)
	}
}

// TestCLIAuthCheckinRequiresKey proves the H5 fix at the CLI: a switch initialized
// with --auth-checkin (and NO on-host key) refuses a plain check-in and accepts a
// check-in signed with the owner-held key.
func TestCLIAuthCheckinRequiresKey(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))
	// Non-dev init: capture the printed check-in private key, nothing on host.
	out := run(t, bin, dir, nil, "init", "--auth-checkin")
	keyFile := filepath.Join(dir, "owner-checkin.key")
	must(t, os.WriteFile(keyFile, []byte(extractKeyAfter(out, "CHECK-IN KEY", "dms-sign-sk-")), 0o600))

	// The host must NOT hold the check-in private key.
	if fileExists(filepath.Join(dir, "keys", "checkin.key")) {
		t.Error("non-dev init must not persist the check-in private key")
	}

	// A plain check-in (no key) must be refused.
	cmd := exec.Command(bin, "checkin")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	pout, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("plain checkin should be refused on an auth switch:\n%s", pout)
	}
	if !strings.Contains(string(pout), "signed check-in") {
		t.Errorf("expected a signed-check-in requirement error, got: %s", pout)
	}

	// A signed check-in using the owner-held key must succeed.
	signedOut := run(t, bin, dir, nil, "checkin", "--checkin-key", keyFile)
	if !strings.Contains(signedOut, "checked in") {
		t.Errorf("signed check-in failed: %s", signedOut)
	}
}

// extractKeyAfter returns the first line starting with prefix that appears AFTER
// a line containing marker — used to grab the right key when several are printed.
func extractKeyAfter(out, marker, prefix string) string {
	seen := false
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, marker) {
			seen = true
			continue
		}
		if seen && strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// TestCLIEnvFuseIgnoredWithoutDemo proves the H8 fix: a leftover DMS_FIRE env var
// must NOT shorten the fuse unless --demo is explicitly passed, so a stray env
// value can't silently arm a hair-trigger in production.
func TestCLIEnvFuseIgnoredWithoutDemo(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))
	run(t, bin, dir, nil, "init", "--dev")
	run(t, bin, dir, nil, "seal", "secret.txt")

	// Hostile/leftover env that would fire instantly IF honored — but no --demo.
	env := []string{"DMS_FIRE_AFTER_MINUTES=0", "DMS_WARN_AFTER_MINUTES=0"}
	out := run(t, bin, dir, env, "watch")
	if strings.Contains(out, "action=fired") {
		t.Fatalf("env var shortened the fuse WITHOUT --demo (H8): %s", out)
	}
	// With --demo the same env DOES fire (compressed-timer path still works).
	demoOut := run(t, bin, dir, env, "--demo", "watch")
	if !strings.Contains(demoOut, "action=fired") {
		t.Errorf("--demo should honor env overrides: %s", demoOut)
	}
}

// TestCLIWatchFailsLoudOnUninitialized proves the C3 fix: running `watch` where
// no switch is initialized must EXIT NONZERO and say so, never silently no-op
// (the canonical way a misconfigured cron unit dies without anyone noticing).
func TestCLIWatchFailsLoudOnUninitialized(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir() // empty: no config, no state

	cmd := exec.Command(bin, "watch")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("watch on an uninitialized dir should fail loudly, got success:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "not initialized") {
		t.Errorf("expected a 'not initialized' error, got: %s", out)
	}
}

// TestCLIDirResolvesHome proves `--dir`/DMS_HOME let a scheduler run watch from
// anywhere (not cwd): a switch initialized in one dir is operable via --dir from
// an unrelated working directory.
func TestCLIDirResolvesHome(t *testing.T) {
	bin := buildDMS(t)
	home := t.TempDir()
	must(t, os.WriteFile(filepath.Join(home, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))
	run(t, bin, home, nil, "init", "--dev")

	// Run watch from a DIFFERENT cwd, pointing at home via --dir.
	elsewhere := t.TempDir()
	out := run(t, bin, elsewhere, nil, "--dir", home, "watch")
	if !strings.Contains(out, "stage=") {
		t.Errorf("watch via --dir did not operate the switch: %s", out)
	}
}

// TestCLIHostHoldsNoPrivateKeys proves the H1 fix: a normal (non-dev) init leaves
// NO private key material on the host — only public keys and ciphertext.
func TestCLIHostHoldsNoPrivateKeys(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	out := run(t, bin, dir, nil, "init") // no --dev

	// The owner private signing key and beneficiary private key must be printed
	// (so the user can save them) but never written to disk.
	if !strings.Contains(out, "BENEFICIARY PRIVATE KEY") || !strings.Contains(out, "OWNER SIGNING KEY") {
		t.Errorf("init should print both private keys once: %s", out)
	}
	for _, f := range []string{"keys/beneficiary.key", "keys/owner-sign.key", "keys/owner.key"} {
		if fileExists(filepath.Join(dir, f)) {
			t.Errorf("H1 violation: private key persisted on host: %s", f)
		}
	}
	// Recipients must NOT include an owner key (owner is not a decryption recipient).
	rec := ""
	if b, err := os.ReadFile(filepath.Join(dir, "keys", "recipients.txt")); err == nil {
		rec = string(b)
	}
	if strings.Count(strings.TrimSpace(rec), "\n") > 0 {
		t.Errorf("recipients should contain only the beneficiary key, got: %q", rec)
	}
}

// TestCLIForgedVaultRejected proves the H3 fix: a vault whose ciphertext was
// substituted (not signed by the owner) is refused by verify.
func TestCLIForgedVaultRejected(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("real"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))

	run(t, bin, dir, nil, "init", "--dev")
	run(t, bin, dir, nil, "seal", "secret.txt")

	// Attacker substitutes the vault with one encrypted to the (public) beneficiary
	// key but NOT signed by the owner. Re-seal a different payload to a throwaway
	// recipient is overkill; simplest: corrupt the ciphertext so the signature no
	// longer matches.
	vaultPath := filepath.Join(dir, "vault.age")
	b, _ := os.ReadFile(vaultPath)
	b[len(b)-1] ^= 0xff
	must(t, os.WriteFile(vaultPath, b, 0o600))

	cmd := exec.Command(bin, "verify")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify accepted a tampered/forged vault:\n%s", out)
	}
	if !strings.Contains(string(out), "PROVENANCE CHECK FAILED") {
		t.Errorf("expected provenance failure, got: %s", out)
	}
}

// TestCLIArweaveNonDryRunRefuses proves the anti-footgun: a non-dry-run arweave
// config must refuse (not silently no-op), so the switch never marks itself fired
// while delivering nothing. With no wallet configured, a real Arweave upload
// cannot proceed, so the switch must refuse rather than fire-without-delivering.
func TestCLIArweaveNonDryRunRefuses(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	// Initialize with safe file storage, then misconfigure arweave and confirm the
	// fire path (watch) refuses rather than firing without a way to deliver.
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"file","notifier":"stdout","dry_run":true}`), 0o600))
	run(t, bin, dir, nil, "init", "--dev")
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"storage":"arweave","dry_run":false,"notifier":"stdout"}`), 0o600))

	cmd := exec.Command(bin, "watch")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected refusal for arweave+dry_run=false without wallet, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "arweave_wallet") {
		t.Errorf("expected an arweave_wallet requirement error, got: %s", out)
	}
}

// TestCLITimelockArmRecover drives the durable construction through the binary
// against the LIVE drand quicknet beacon: arm with a short unlock, confirm it is
// locked now, wait for the round, then recover with the timelocked share + the
// beneficiary shares. Tagged integration (real network); skipped in the fast run.
func TestCLITimelockArmRecover(t *testing.T) {
	if os.Getenv("DMS_INTEGRATION") == "" {
		t.Skip("set DMS_INTEGRATION=1 to run the live drand timelock CLI test")
	}
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "note.txt"), []byte("durable payload"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"shamir_n":3,"shamir_k":2}`), 0o600))

	// Arm with a ~12s unlock window.
	offbox := filepath.Join(dir, "MOVE-OFFBOX-then-delete")
	armOut := run(t, bin, dir, nil, "timelock-arm", "secrets", "--unlock-seconds", "12")
	if !strings.Contains(armOut, "armed") {
		t.Fatalf("arm output unexpected: %s", armOut)
	}
	if !fileExists(filepath.Join(dir, "share-timelocked.age")) ||
		!fileExists(filepath.Join(offbox, "share-beneficiary-1.txt")) {
		t.Fatal("arm did not write share files")
	}

	// Wait for the unlock round, then recover (beneficiary shares from off-box dir).
	time.Sleep(20 * time.Second)
	recOut := run(t, bin, dir, nil, "timelock-recover", "--shares-dir", offbox, "--out", filepath.Join(dir, "out"))
	if !strings.Contains(recOut, "recovered") {
		t.Fatalf("recover output unexpected: %s", recOut)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out", "secrets", "note.txt"))
	if err != nil || string(got) != "durable payload" {
		t.Fatalf("recovered payload wrong: %q err=%v", got, err)
	}
}

// TestCLITimelockReArm proves the H7 fix through the binary against live drand:
// arm with a long deadline, re-arm to a short one (reusing the same share), and
// confirm recovery still works with the ORIGINAL beneficiary shares once the new
// round opens — i.e. re-arming tracks liveness without orphaning shares.
func TestCLITimelockReArm(t *testing.T) {
	if os.Getenv("DMS_INTEGRATION") == "" {
		t.Skip("set DMS_INTEGRATION=1 to run the live drand re-arm CLI test")
	}
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "note.txt"), []byte("rearm payload"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"shamir_n":3,"shamir_k":2}`), 0o600))

	// Arm far in the future.
	offbox := filepath.Join(dir, "MOVE-OFFBOX-then-delete")
	run(t, bin, dir, nil, "timelock-arm", "secrets", "--unlock-seconds", "31536000")
	// Capture the beneficiary share now; it must remain valid after re-arm.
	origShare, err := os.ReadFile(filepath.Join(offbox, "share-beneficiary-1.txt"))
	must(t, err)

	// Re-arm to a short window, supplying the owner raw share (not kept on host).
	rawShare := filepath.Join(offbox, "share-raw-owner.txt")
	reOut := run(t, bin, dir, nil, "timelock-rearm", "--raw-share", rawShare, "--unlock-seconds", "12")
	if !strings.Contains(reOut, "re-armed") {
		t.Fatalf("rearm output unexpected: %s", reOut)
	}
	// The beneficiary share file must be unchanged by re-arm.
	newShare, _ := os.ReadFile(filepath.Join(offbox, "share-beneficiary-1.txt"))
	if string(origShare) != string(newShare) {
		t.Fatal("re-arm changed the beneficiary share — would orphan distributed shares")
	}

	// After the new short round opens, recover with the original shares.
	time.Sleep(20 * time.Second)
	recOut := run(t, bin, dir, nil, "timelock-recover", "--shares-dir", offbox, "--out", filepath.Join(dir, "out"))
	if !strings.Contains(recOut, "recovered") {
		t.Fatalf("recover after re-arm failed: %s", recOut)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out", "secrets", "note.txt"))
	if err != nil || string(got) != "rearm payload" {
		t.Fatalf("re-armed recovery wrong: %q err=%v", got, err)
	}
}

// TestCLITimelockArmNoKeySubsetOnHost proves the D5 + share-raw fix: after a
// default timelock-arm, the switch home dir must NOT contain a K-of-N subset of
// shares (which would reconstruct the full key on the watch host). The host keeps
// only the timelocked blob; the raw share and beneficiary shares go to a separate
// "move me off-box" directory.
func TestCLITimelockArmNoKeySubsetOnHost(t *testing.T) {
	if os.Getenv("DMS_INTEGRATION") == "" {
		t.Skip("set DMS_INTEGRATION=1 (needs live drand) for timelock-arm layout test")
	}
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "n.txt"), []byte("x"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"shamir_n":3,"shamir_k":2}`), 0o600))

	out := run(t, bin, dir, nil, "timelock-arm", "secrets", "--unlock-seconds", "31536000")

	// The home dir must hold the timelocked blob but NOT raw/beneficiary shares.
	if !fileExists(filepath.Join(dir, "share-timelocked.age")) {
		t.Fatal("home should keep the timelocked blob")
	}
	homeShares, _ := filepath.Glob(filepath.Join(dir, "share-beneficiary-*.txt"))
	if len(homeShares) != 0 {
		t.Errorf("beneficiary shares must NOT remain in the switch home: %v", homeShares)
	}
	if fileExists(filepath.Join(dir, "share-raw.local")) {
		t.Error("raw share must NOT remain in the switch home (it completes a K-subset)")
	}
	// The off-box material must be written to a clearly-labelled separate dir and
	// the command must warn about moving it.
	if !strings.Contains(strings.ToLower(out), "off") {
		t.Errorf("arm should warn to move shares off-box: %s", out)
	}
}

// TestCLIQuickstart drives the non-interactive quickstart: it should init keys,
// seal the given path, write config, and emit a recovery card — all in one go,
// with no Arweave wallet or tokens required.
func TestCLIQuickstart(t *testing.T) {
	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "secrets", "note.txt"), []byte("hi"), 0o600))

	out := run(t, bin, dir, nil, "quickstart",
		"--owner", "John", "--path", "secrets", "--yes")
	if !strings.Contains(out, "ready") {
		t.Fatalf("quickstart output unexpected: %s", out)
	}
	for _, f := range []string{"config.json", "vault.age", "vault.age.sig", "keys/recipients.txt", "RECOVERY-CARD.txt"} {
		if !fileExists(filepath.Join(dir, f)) {
			t.Errorf("quickstart did not create %s", f)
		}
	}
	// H2: the easy path must NOT persist the beneficiary private key on the host;
	// it must be printed once instead.
	if fileExists(filepath.Join(dir, "keys", "beneficiary.key")) {
		t.Error("H2 violation: quickstart persisted beneficiary.key on the host")
	}
	if !strings.Contains(out, "BENEFICIARY PRIVATE KEY") {
		t.Error("quickstart should print the beneficiary private key once")
	}
	// The switch must be armed and healthy afterwards.
	if st := run(t, bin, dir, nil, "status", "--json"); !strings.Contains(st, `"stage": "HEALTHY"`) {
		t.Errorf("after quickstart expected HEALTHY: %s", st)
	}
}

// TestCLIArweaveFireDelivers proves the full fire path with REAL Arweave delivery
// against the arlocal devnet: configure an arweave wallet, fire via compressed
// timers, and confirm the released ciphertext is fetchable from the node. Run
// with DMS_INTEGRATION=1 and arlocal on :1985.
func TestCLIArweaveFireDelivers(t *testing.T) {
	if os.Getenv("DMS_INTEGRATION") == "" {
		t.Skip("set DMS_INTEGRATION=1 (and run arlocal on :1985) for the Arweave fire test")
	}
	const arlocal = "http://127.0.0.1:1985"
	if resp, err := http.Get(arlocal + "/info"); err != nil {
		t.Skipf("arlocal not reachable: %v", err)
	} else {
		resp.Body.Close()
	}

	bin := buildDMS(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("arweave delivery payload"), 0o600))

	// Generate an Arweave wallet and mint devnet funds.
	walletPath := filepath.Join(dir, "wallet.json")
	addr := writeFundedWallet(t, walletPath, arlocal)

	cfg := `{"storage":"arweave","dry_run":false,"notifier":"stdout",` +
		`"arweave_url":"` + arlocal + `","arweave_wallet":"wallet.json"}`
	must(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600))

	run(t, bin, dir, nil, "init", "--dev")
	run(t, bin, dir, nil, "seal", "secret.txt")

	// Fire via compressed timers.
	fireEnv := []string{"DMS_WARN_AFTER_MINUTES=0", "DMS_FIRE_AFTER_MINUTES=0"}
	out := run(t, bin, dir, fireEnv, "--demo", "watch")
	if !strings.Contains(out, "action=fired") {
		t.Fatalf("expected fire, got: %s", out)
	}
	// The notifier prints the locator (gateway/<txid>); extract and fetch it.
	_ = addr
	txURL := extractLocator(out)
	if txURL == "" {
		t.Fatalf("no arweave locator in fire output: %s", out)
	}
	// Mine the pending tx, then fetch the stored ciphertext back.
	http.Get(arlocal + "/mine")
	resp, err := http.Get(txURL)
	if err != nil {
		t.Fatalf("fetch %s: %v", txURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("fetch %s: HTTP %d", txURL, resp.StatusCode)
	}
	// The fetched bytes are the age ciphertext; confirm it's an age file.
	buf := make([]byte, 32)
	n, _ := resp.Body.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "age-encryption.org") {
		t.Errorf("fetched data is not the age ciphertext: %q", buf[:n])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
