// Package shamir implements Shamir's Secret Sharing over GF(2^8). It is
// self-contained (no external dependency) so the security-critical core stays
// small and auditable. A secret is split into N shares such that any K combine
// to recover it, while any K-1 reveal information-theoretically nothing.
//
// Each share is the byte-wise evaluation of per-byte degree-(K-1) polynomials at
// a distinct non-zero x, encoded as [x-coordinate ‖ y-bytes...].
package shamir

import (
	"crypto/rand"
	"fmt"
)

// gfMul multiplies two elements of GF(2^8) using the AES (Rijndael) reduction
// polynomial 0x11b, via Russian-peasant multiplication.
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// gfInv returns the multiplicative inverse of a in GF(2^8) (a != 0), computed as
// a^254 by repeated squaring/multiplication.
func gfInv(a byte) byte {
	var result byte = 1
	for range 254 {
		result = gfMul(result, a)
	}
	return result
}

// Split divides secret into n shares with reconstruction threshold k. It returns
// n byte slices, each prefixed with its unique x-coordinate.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 {
		return nil, fmt.Errorf("threshold k must be >= 2 (got %d)", k)
	}
	if n < k {
		return nil, fmt.Errorf("shares n (%d) must be >= threshold k (%d)", n, k)
	}
	if n > 255 {
		return nil, fmt.Errorf("shares n must be <= 255 (got %d)", n)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}

	// Distinct non-zero x-coordinates 1..n.
	shares := make([][]byte, n)
	for i := range n {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1)
	}

	// For each secret byte, build a random degree-(k-1) polynomial whose constant
	// term is the secret byte, then evaluate at each x.
	coeffs := make([]byte, k)
	for bi, sb := range secret {
		coeffs[0] = sb
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for si := range n {
			shares[si][bi+1] = evalPoly(coeffs, shares[si][0])
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from shares via Lagrange interpolation at x=0.
// It requires at least the original threshold number of distinct shares; fewer
// shares yield a value unrelated to the secret.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares to combine (got %d)", len(shares))
	}
	length := len(shares[0])
	if length < 2 {
		return nil, fmt.Errorf("malformed share")
	}
	xs := make([]byte, len(shares))
	seen := make(map[byte]bool)
	for i, s := range shares {
		if len(s) != length {
			return nil, fmt.Errorf("inconsistent share lengths")
		}
		x := s[0]
		if x == 0 {
			return nil, fmt.Errorf("invalid share x-coordinate 0")
		}
		if seen[x] {
			return nil, fmt.Errorf("duplicate share x-coordinate %d", x)
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, length-1)
	for bi := 0; bi < length-1; bi++ {
		ys := make([]byte, len(shares))
		for i, s := range shares {
			ys[i] = s[bi+1]
		}
		secret[bi] = lagrangeAtZero(xs, ys)
	}
	return secret, nil
}

// evalPoly evaluates a polynomial (coeffs[0] + coeffs[1]x + ...) at x in GF(2^8).
func evalPoly(coeffs []byte, x byte) byte {
	var result byte
	// Horner's method, high degree to low.
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// lagrangeAtZero interpolates the polynomial through (xs,ys) and returns its
// value at x=0 (the secret byte).
func lagrangeAtZero(xs, ys []byte) byte {
	var secret byte
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gfMul(num, xs[j])
			den = gfMul(den, xs[i]^xs[j])
		}
		term := gfMul(ys[i], gfMul(num, gfInv(den)))
		secret ^= term
	}
	return secret
}
