// Package timelock wraps drand timelock encryption (tlock) so that a single
// Shamir share can be sealed to a future drand round and only becomes decryptable
// once the League of Entropy publishes that round's signature. Per TIMELOCK.md the
// switch only ever timelocks ONE share — never the secret — so a public unlock
// leaks nothing.
package timelock

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

// quicknet is the drand beacon that supports timelock (3s rounds, unchained BLS).
const (
	QuicknetHost  = "https://api.drand.sh"
	QuicknetChain = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

// RoundForTime computes the drand round whose signature is published at or after
// t, given a beacon genesis (unix seconds) and period. This is the round_for(T)
// formula from TIMELOCK.md: floor((T-genesis)/period)+1, clamped to >= 1.
func RoundForTime(t time.Time, genesisUnix int64, period time.Duration) uint64 {
	delta := t.Unix() - genesisUnix
	if delta < 0 {
		return 1
	}
	return uint64(delta/int64(period.Seconds())) + 1
}

// SealToRound timelock-encrypts data so it can only be decrypted once the given
// drand round is reached. Output is an age-format file.
func SealToRound(net tlock.Network, round uint64, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := tlock.New(net).Encrypt(&buf, bytes.NewReader(data), round); err != nil {
		return nil, fmt.Errorf("timelock encrypt: %w", err)
	}
	return buf.Bytes(), nil
}

// OpenFromRound attempts to decrypt a timelocked blob. It fails until the beacon
// has published the signature for the embedded round.
func OpenFromRound(net tlock.Network, sealed []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := tlock.New(net).Decrypt(&buf, bytes.NewReader(sealed)); err != nil {
		return nil, err
	}
	return io.ReadAll(&buf)
}

// QuicknetNetwork connects to the live drand quicknet beacon used for timelock.
func QuicknetNetwork() (tlock.Network, error) {
	net, err := http.NewNetwork(QuicknetHost, QuicknetChain)
	if err != nil {
		return nil, fmt.Errorf("connect quicknet: %w", err)
	}
	return net, nil
}
