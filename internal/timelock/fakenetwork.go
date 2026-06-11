package timelock

import (
	"fmt"
	"time"

	chain "github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/drand/kyber/util/random"
)

// FakeNetwork is an in-memory drand stand-in for unit tests. It plays the role of
// the League of Entropy as a private key generator: it holds a BLS keypair on the
// quicknet scheme and will produce the signature for a round only after that round
// has been "published". This lets tests prove the lock/unlock transition without
// the live beacon. It implements tlock.Network.
type FakeNetwork struct {
	scheme    *crypto.Scheme
	secret    kyber.Scalar
	public    kyber.Point
	period    time.Duration
	genesis   int64
	published uint64 // highest round whose signature is available
}

// NewFakeNetwork builds a fake network with a fresh keypair and quicknet-like
// parameters (3s rounds), starting with no rounds published.
func NewFakeNetwork() *FakeNetwork {
	sch := crypto.NewPedersenBLSUnchainedG1()
	secret := sch.KeyGroup.Scalar().Pick(random.New())
	public := sch.KeyGroup.Point().Mul(secret, nil)
	return &FakeNetwork{
		scheme:  sch,
		secret:  secret,
		public:  public,
		period:  3 * time.Second,
		genesis: time.Now().Add(-time.Hour).Unix(),
	}
}

// PublishUpTo makes signatures for all rounds <= round available for decryption,
// simulating the beacon advancing to that round.
func (f *FakeNetwork) PublishUpTo(round uint64) { f.published = round }

// ChainHash returns a stable fake chain hash.
func (f *FakeNetwork) ChainHash() string {
	return "fakefakefakefakefakefakefakefakefakefakefakefakefakefakefakefake"
}

// Current returns the round number active at time t for this fake's parameters.
func (f *FakeNetwork) Current(t time.Time) uint64 {
	return RoundForTime(t, f.genesis, f.period)
}

// PublicKey returns the beacon public key.
func (f *FakeNetwork) PublicKey() kyber.Point { return f.public }

// Scheme returns the drand crypto scheme in use.
func (f *FakeNetwork) Scheme() crypto.Scheme { return *f.scheme }

// SwitchChainHash is a no-op for the fake.
func (f *FakeNetwork) SwitchChainHash(string) error { return nil }

// Signature returns the BLS signature over the round, but only if that round has
// been published; otherwise it errors, modelling "the future hasn't happened yet".
func (f *FakeNetwork) Signature(round uint64) ([]byte, error) {
	if round > f.published {
		return nil, fmt.Errorf("round %d not yet available (published up to %d)", round, f.published)
	}
	msg := f.scheme.DigestBeacon(&chain.Beacon{Round: round})
	sig, err := f.scheme.AuthScheme.Sign(f.secret, msg)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
