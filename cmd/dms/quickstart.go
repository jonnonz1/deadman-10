package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jonnonz1/deadman-10/internal/keys"
	"github.com/jonnonz1/deadman-10/internal/recoverycard"
	"github.com/jonnonz1/deadman-10/internal/signing"
	"github.com/jonnonz1/deadman-10/internal/vault"
)

// cmdQuickstart is the "really easy to set up" path: one interactive command that
// generates keys, seals a file/folder, arms the switch, and prints the
// beneficiary recovery card. No Arweave wallet or tokens are required. Flags make
// it scriptable: --owner, --path, --beneficiary, --yes (non-interactive).
func cmdQuickstart() {
	cfg, root := loadCfg()
	reader := bufio.NewReader(os.Stdin)
	yes := hasFlag("--yes")

	owner := flagValue("--owner")
	if owner == "" {
		owner = prompt(reader, yes, "Your name", cfg.OwnerName)
	}
	path := flagValue("--path")
	if path == "" {
		path = prompt(reader, yes, "File or folder to protect", "secrets")
	}
	beneficiary := flagValue("--beneficiary")
	if beneficiary == "" && !yes {
		beneficiary = prompt(reader, yes, "Beneficiary name (optional)", "")
	}

	if _, err := os.Stat(path); err != nil {
		fail(fmt.Errorf("cannot protect %q: %w", path, err))
	}

	// --dev retains private keys on the host for local testing; the default keeps
	// the host ciphertext-only (threat model H1/H2).
	dev := hasFlag("--dev")
	keysDir := abs(root, cfg.KeysDir)
	must(os.MkdirAll(keysDir, 0o700))
	must(os.MkdirAll(abs(root, cfg.StateDir), 0o700))

	benKP, err := keys.Generate()
	must(err)
	ownerSign, err := signing.Generate()
	must(err)

	// Host keeps only public material; the vault is encrypted to the beneficiary
	// only (the owner is not a decryption recipient).
	must(os.WriteFile(filepath.Join(keysDir, "beneficiary.pub"), []byte(benKP.Public+"\n"), 0o600))
	must(os.WriteFile(filepath.Join(keysDir, "owner-sign.pub"), []byte(ownerSign.Public+"\n"), 0o600))
	must(os.WriteFile(abs(root, cfg.RecipientsFile), []byte(benKP.Public+"\n"), 0o600))
	if dev {
		must(os.WriteFile(filepath.Join(keysDir, "beneficiary.key"), []byte(benKP.Private+"\n"), 0o600))
		must(os.WriteFile(filepath.Join(keysDir, "owner-sign.key"), []byte(ownerSign.Private+"\n"), 0o600))
	}

	vaultPath := abs(root, cfg.VaultPath)
	if _, err := vault.Seal(path, []string{benKP.Public}, vaultPath); err != nil {
		fail(err)
	}
	// Sign the ciphertext for provenance (H3).
	ciphertext, err := os.ReadFile(vaultPath)
	must(err)
	sig, err := signing.Sign(ownerSign.Private, ciphertext)
	must(err)
	must(os.WriteFile(vaultPath+".sig", sig, 0o600))

	cfg.OwnerName = owner
	must(cfg.Save(filepath.Join(root, "config.json")))

	e := newEngine(cfg, root)
	must(e.Checkin())

	card := recoverycard.Render(recoverycard.Data{
		OwnerName:       owner,
		BeneficiaryName: beneficiary,
		Mode:            recoverycard.ModeSimple,
		OwnerSignPublic: ownerSign.Public,
	})
	cardPath := filepath.Join(root, "RECOVERY-CARD.txt")
	must(os.WriteFile(cardPath, []byte(card), 0o600))

	fmt.Println()
	fmt.Println("✅ deadman-10 is ready and armed. The host holds only PUBLIC keys.")
	fmt.Printf("   protected      : %s -> %s (encrypted + signed)\n", path, cfg.VaultPath)
	fmt.Printf("   warns after    : %v ; fires after : %v\n", cfg.WarnAfter(), cfg.FireAfter())
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("SAVE THESE PRIVATE KEYS OFFLINE NOW — they are not stored on the host:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("BENEFICIARY PRIVATE KEY (give to your beneficiary; opens the vault):")
	fmt.Println(benKP.Private)
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("OWNER SIGNING KEY (keep yourself; needed to re-seal):")
	fmt.Println(ownerSign.Private)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("NEXT STEPS:")
	fmt.Println("  1. Give your beneficiary their private key + RECOVERY-CARD.txt, OFFLINE.")
	fmt.Println("  2. Schedule `dms watch` (cron/launchd/an always-on host) so the timer runs.")
	fmt.Println("  3. Run `dms checkin` regularly to prove you're alive.")
	fmt.Println("  4. Tighten thresholds in config.json (default: warn 7d, fire 21d).")
	if dev {
		fmt.Println("[dev] private keys also saved under keys/ for local testing only.")
	}
}

// prompt reads a line with a default; in --yes mode it returns the default
// without blocking.
func prompt(r *bufio.Reader, yes bool, label, def string) string {
	if yes {
		return def
	}
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}
