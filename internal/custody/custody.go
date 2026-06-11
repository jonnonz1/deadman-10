// Package custody implements the durable, no-operator construction from
// TIMELOCK.md §6: the payload is sealed to an ephemeral age key, that key is
// split K-of-N with Shamir, and exactly ONE share is timelock-encrypted to a
// future drand round. The beneficiary holds K-1 shares offline.
//
// The security property (§6.2): when the timelocked share becomes public at the
// unlock time, it is a single Shamir share and reveals nothing. Only the party
// also holding the other K-1 shares can reconstruct the key and open the vault.
package custody

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/drand/tlock"
	"github.com/jonnonz1/deadman-10/internal/shamir"
	"github.com/jonnonz1/deadman-10/internal/timelock"
	"github.com/jonnonz1/deadman-10/internal/vault"
)

// ArmConfig parameterises the share-timelock construction.
type ArmConfig struct {
	Source         string        // file or folder to seal
	VaultPath      string        // where the ciphertext is written
	OwnerRecipient string        // optional owner age recipient for always-recover
	ShamirN        int           // total shares
	ShamirK        int           // reconstruction threshold
	Network        tlock.Network // drand network (real or fake)
	UnlockRound    uint64        // drand round at which the timelocked share opens
}

// Armed is the output of Arm: what to keep, hand out, and publish.
type Armed struct {
	VaultPath         string
	K                 int
	N                 int
	UnlockRound       uint64
	TimelockedShare   []byte   // the timelocked blob (mutable storage only — see ReArm)
	RawTimelockShare  []byte   // the unencrypted share inside it; keep locally to re-arm
	BeneficiaryShares [][]byte // hand these (K-1) to the beneficiary, offline
}

// Arm performs the construction. The ephemeral identity exists only long enough
// to seal the vault and be split; it is never written to disk whole.
func Arm(cfg ArmConfig) (*Armed, error) {
	if cfg.ShamirK < 2 {
		return nil, fmt.Errorf("shamir K must be >= 2")
	}
	if cfg.ShamirN < cfg.ShamirK {
		return nil, fmt.Errorf("shamir N (%d) must be >= K (%d)", cfg.ShamirN, cfg.ShamirK)
	}

	// 1. Ephemeral age key the vault is sealed to.
	eph, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	recipients := []string{eph.Recipient().String()}
	if cfg.OwnerRecipient != "" {
		recipients = append(recipients, cfg.OwnerRecipient)
	}

	// 2. Seal the payload to the ephemeral (and owner) recipient(s).
	if _, err := vault.Seal(cfg.Source, recipients, cfg.VaultPath); err != nil {
		return nil, fmt.Errorf("seal vault: %w", err)
	}

	// 3. Split the ephemeral identity string K-of-N.
	shares, err := shamir.Split([]byte(eph.String()), cfg.ShamirN, cfg.ShamirK)
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	// 4. Timelock exactly ONE share to the unlock round; keep the rest for the
	//    beneficiary. K-1 are needed alongside the timelocked one to reach K.
	timelocked, err := timelock.SealToRound(cfg.Network, cfg.UnlockRound, shares[0])
	if err != nil {
		return nil, fmt.Errorf("timelock share: %w", err)
	}
	beneficiary := shares[1:cfg.ShamirK] // exactly K-1 shares

	return &Armed{
		VaultPath:         cfg.VaultPath,
		K:                 cfg.ShamirK,
		N:                 cfg.ShamirN,
		UnlockRound:       cfg.UnlockRound,
		TimelockedShare:   timelocked,
		RawTimelockShare:  shares[0],
		BeneficiaryShares: beneficiary,
	}, nil
}

// ReArmConfig parameterises pushing the unlock deadline forward on check-in.
type ReArmConfig struct {
	RawTimelockShare []byte // the same share bytes Arm timelocked (kept locally)
	Network          tlock.Network
	UnlockRound      uint64 // the new, later round
}

// ReArmed is the output of ReArm.
type ReArmed struct {
	UnlockRound     uint64
	TimelockedShare []byte // overwrite the previous (mutable) timelocked blob with this
}

// ReArm re-timelocks the SAME share to a later round, coupling the unlock to
// liveness (threat-model H7) WITHOUT regenerating the key — so already-distributed
// beneficiary shares stay valid.
//
// Critical constraint: this only achieves liveness-coupling if the timelocked
// share lives on MUTABLE, replaceable storage (a local file, or a pointer the
// host advances). If an older short-deadline blob was published to PERMANENT
// storage (e.g. Arweave), it still opens at its original round and the deadline
// cannot be moved — the vault ciphertext may be permanent, but the timelocked
// share must not be.
func ReArm(cfg ReArmConfig) (*ReArmed, error) {
	if len(cfg.RawTimelockShare) == 0 {
		return nil, fmt.Errorf("re-arm needs the raw timelock share from the original Arm")
	}
	timelocked, err := timelock.SealToRound(cfg.Network, cfg.UnlockRound, cfg.RawTimelockShare)
	if err != nil {
		return nil, fmt.Errorf("re-timelock share: %w", err)
	}
	return &ReArmed{UnlockRound: cfg.UnlockRound, TimelockedShare: timelocked}, nil
}

// RecoverConfig parameterises reconstruction. Provide either the timelocked share
// plus the beneficiary shares (the normal path), or RawShares directly (used to
// test what a holder of specific shares can do).
type RecoverConfig struct {
	VaultPath         string
	TimelockedShare   []byte
	BeneficiaryShares [][]byte
	RawShares         [][]byte // already-unlocked shares, bypassing timelock
	Network           tlock.Network
	DestDir           string
}

// Recovered reports where the payload was extracted.
type Recovered struct {
	DestDir string
}

// Recover reconstructs the ephemeral key from available shares and opens the
// vault. It fails if fewer than K valid shares are available (including when the
// timelocked share has not yet unlocked).
func Recover(cfg RecoverConfig) (*Recovered, error) {
	var shares [][]byte
	shares = append(shares, cfg.RawShares...)
	shares = append(shares, cfg.BeneficiaryShares...)

	if len(cfg.TimelockedShare) > 0 {
		raw, err := timelock.OpenFromRound(cfg.Network, cfg.TimelockedShare)
		if err != nil {
			return nil, fmt.Errorf("timelocked share not yet available: %w", err)
		}
		shares = append(shares, raw)
	}

	identityBytes, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}
	identity := strings.TrimSpace(string(identityBytes))
	if !strings.HasPrefix(identity, "AGE-SECRET-KEY-1") {
		// Below threshold: shamir returns junk that is not a valid key.
		return nil, fmt.Errorf("insufficient shares to reconstruct key")
	}
	if err := os.MkdirAll(cfg.DestDir, 0o700); err != nil {
		return nil, err
	}
	if err := vault.Open(cfg.VaultPath, identity, cfg.DestDir); err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	return &Recovered{DestDir: cfg.DestDir}, nil
}
