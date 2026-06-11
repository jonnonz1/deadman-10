package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jonnonz1/deadman-10/internal/custody"
	"github.com/jonnonz1/deadman-10/internal/recoverycard"
	"github.com/jonnonz1/deadman-10/internal/timelock"
)

// cmdTimelockArm seals a file/folder under the durable share-timelock construction
// (TIMELOCK.md §6): the vault key is split K-of-N, one share is timelocked to a
// future drand round, and the beneficiary's K-1 shares are written to disk for
// offline custody. The timelocked share is public-safe.
func cmdTimelockArm() {
	if len(os.Args) < 3 {
		fail(fmt.Errorf("usage: dms timelock-arm <path> [--unlock-seconds N]"))
	}
	src := os.Args[2]
	cfg, root := loadCfg()

	unlockSecs := 365 * 24 * 3600 // default: ~1 year out (long-T backstop)
	if v := flagValue("--unlock-seconds"); v != "" {
		n, err := strconv.Atoi(v)
		must(err)
		unlockSecs = n
	}

	net, err := timelock.QuicknetNetwork()
	must(err)
	unlockAt := time.Now().Add(time.Duration(unlockSecs) * time.Second)
	round := net.Current(unlockAt)

	armed, err := custody.Arm(custody.ArmConfig{
		Source:      src,
		VaultPath:   abs(root, cfg.VaultPath),
		ShamirN:     cfg.ShamirN,
		ShamirK:     cfg.ShamirK,
		Network:     net,
		UnlockRound: round,
	})
	must(err)

	// The switch HOME keeps ONLY the timelocked blob (safe alone) + the round, so
	// the watch host never holds a K-of-N subset that reconstructs the key
	// (threat model D5). The raw share and the beneficiary shares are written to a
	// SEPARATE, clearly-labelled directory the owner must move off-box.
	must(os.WriteFile(filepath.Join(root, "share-timelocked.age"), armed.TimelockedShare, 0o600))
	must(os.WriteFile(filepath.Join(root, "share-unlock-round.txt"),
		[]byte(strconv.FormatUint(armed.UnlockRound, 10)+"\n"), 0o600))

	offbox := flagValue("--shares-out")
	if offbox == "" {
		offbox = filepath.Join(root, "MOVE-OFFBOX-then-delete")
	}
	must(os.MkdirAll(offbox, 0o700))
	must(os.WriteFile(filepath.Join(offbox, "share-raw-owner.txt"),
		[]byte(base64.StdEncoding.EncodeToString(armed.RawTimelockShare)+"\n"), 0o600))
	for i, s := range armed.BeneficiaryShares {
		name := filepath.Join(offbox, fmt.Sprintf("share-beneficiary-%d.txt", i+1))
		must(os.WriteFile(name, []byte(base64.StdEncoding.EncodeToString(s)+"\n"), 0o600))
	}

	fmt.Printf("armed (%d-of-%d). vault sealed; one share timelocked to drand round %d (~%s).\n",
		armed.K, armed.N, armed.UnlockRound, unlockAt.UTC().Format("2006-01-02 15:04 MST"))
	fmt.Println("KEPT ON THIS HOST (safe alone):")
	fmt.Println("  share-timelocked.age   -> the no-operator backstop (MUTABLE storage only)")
	fmt.Println()
	fmt.Printf("WRITTEN TO %s — MOVE OFF THIS HOST NOW, then delete the directory:\n", offbox)
	fmt.Printf("  share-beneficiary-1..%d.txt -> give to the beneficiary, store OFFLINE\n", armed.K-1)
	fmt.Println("  share-raw-owner.txt         -> owner-only; supply to `dms timelock-rearm --raw-share`")
	fmt.Println()
	fmt.Println("⚠ Leaving the raw share + beneficiary shares on this host gives it a full")
	fmt.Println("  K-of-N key set — the split then protects nothing. Move them off-box.")
	fmt.Println("⚠ Re-arm before the unlock round to couple this to your liveness:")
	fmt.Println("  `dms timelock-rearm --raw-share <share-raw-owner.txt>` on each check-in.")
	fmt.Println("  Do NOT publish share-timelocked.age to permanent storage (e.g. Arweave):")
	fmt.Println("  an un-retractable short-deadline blob would fire on a calendar, not on death.")

	// Write the beneficiary recovery card alongside the shares.
	card := recoverycard.Render(recoverycard.Data{
		OwnerName:   cfg.OwnerName,
		Mode:        recoverycard.ModeTimelock,
		ShamirK:     armed.K,
		ShamirN:     armed.N,
		UnlockRound: armed.UnlockRound,
		UnlockHuman: unlockAt.UTC().Format("2006-01-02 15:04 MST"),
	})
	cardPath := filepath.Join(root, "RECOVERY-CARD.txt")
	must(os.WriteFile(cardPath, []byte(card), 0o600))
	fmt.Printf("  RECOVERY-CARD.txt         -> give to the beneficiary with their shares\n")
}

// cmdTimelockReArm pushes the timelock deadline forward by re-locking the SAME
// share to a later round, so the beneficiary's already-distributed shares stay
// valid (threat-model H7 — liveness coupling). The owner SUPPLIES the raw share
// (--raw-share); it is not kept on the host, so the host never holds a K-subset
// (D5).
func cmdTimelockReArm() {
	_, root := loadCfg()
	rawPath := flagValue("--raw-share")
	if rawPath == "" {
		fail(fmt.Errorf("usage: dms timelock-rearm --raw-share <share-raw-owner.txt> [--unlock-seconds N]\n" +
			"(the raw share is owner-only off-box material from timelock-arm; it is not stored on the host)"))
	}
	if !fileExists(rawPath) {
		fail(fmt.Errorf("raw share file not found: %s", rawPath))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(readFile(rawPath)))
	must(err)

	unlockSecs := 365 * 24 * 3600
	if v := flagValue("--unlock-seconds"); v != "" {
		n, err := strconv.Atoi(v)
		must(err)
		unlockSecs = n
	}
	net, err := timelock.QuicknetNetwork()
	must(err)
	unlockAt := time.Now().Add(time.Duration(unlockSecs) * time.Second)
	round := net.Current(unlockAt)

	rearmed, err := custody.ReArm(custody.ReArmConfig{
		RawTimelockShare: raw,
		Network:          net,
		UnlockRound:      round,
	})
	must(err)

	// Overwrite the mutable timelocked blob and the recorded round.
	must(os.WriteFile(filepath.Join(root, "share-timelocked.age"), rearmed.TimelockedShare, 0o600))
	must(os.WriteFile(filepath.Join(root, "share-unlock-round.txt"),
		[]byte(strconv.FormatUint(rearmed.UnlockRound, 10)+"\n"), 0o600))

	fmt.Printf("re-armed: deadline pushed to drand round %d (~%s).\n",
		rearmed.UnlockRound, unlockAt.UTC().Format("2006-01-02 15:04 MST"))
	fmt.Println("Beneficiary shares are unchanged and remain valid.")
}

// cmdRecoveryCard prints (or writes) the beneficiary recovery card for the
// current switch configuration.
func cmdRecoveryCard() {
	cfg, root := loadCfg()
	mode := recoverycard.ModeSimple
	if fileExists(filepath.Join(root, "share-timelocked.age")) {
		mode = recoverycard.ModeTimelock
	}
	data := recoverycard.Data{
		OwnerName: cfg.OwnerName,
		Mode:      mode,
		ShamirK:   cfg.ShamirK,
		ShamirN:   cfg.ShamirN,
	}
	if r := readOptional(filepath.Join(root, "share-unlock-round.txt")); r != "" {
		fmt.Sscanf(strings.TrimSpace(r), "%d", &data.UnlockRound)
	}
	fmt.Print(recoverycard.Render(data))
}

// readOptional returns a file's contents or "" if it does not exist.
func readOptional(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// cmdTimelockRecover reconstructs the vault from the timelocked share (once its
// drand round is reached) plus the beneficiary's K-1 shares.
func cmdTimelockRecover() {
	cfg, root := loadCfg()
	out := flagValue("--out")
	if out == "" {
		out = filepath.Join(root, "recovered")
	}

	tlShare, err := os.ReadFile(filepath.Join(root, "share-timelocked.age"))
	must(err)

	// Beneficiary shares are off-box material; look in --shares-dir (default: the
	// home dir, e.g. when the beneficiary has gathered everything in one place).
	sharesDir := flagValue("--shares-dir")
	if sharesDir == "" {
		sharesDir = root
	}
	var benShares [][]byte
	entries, _ := filepath.Glob(filepath.Join(sharesDir, "share-beneficiary-*.txt"))
	for _, e := range entries {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(readFile(e)))
		must(err)
		benShares = append(benShares, raw)
	}
	if len(benShares) < cfg.ShamirK-1 {
		fail(fmt.Errorf("need %d beneficiary shares in %s, found %d (use --shares-dir)",
			cfg.ShamirK-1, sharesDir, len(benShares)))
	}

	net, err := timelock.QuicknetNetwork()
	must(err)

	rec, err := custody.Recover(custody.RecoverConfig{
		VaultPath:         abs(root, cfg.VaultPath),
		TimelockedShare:   tlShare,
		BeneficiaryShares: benShares,
		Network:           net,
		DestDir:           out,
	})
	must(err)
	fmt.Printf("recovered -> %s\n", rec.DestDir)
	printTree(rec.DestDir)
}
