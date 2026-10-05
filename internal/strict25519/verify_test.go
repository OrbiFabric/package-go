// SPDX-License-Identifier: Apache-2.0
package strict25519

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"
)

// Test-only affine group operations construct adversarial points/signatures.
// They are independent of Go's optimized equation verifier and are never used
// with production secrets or exposed by the public SDK.
func addTest(a, b point) point {
	prod := mod(new(big.Int).Mul(curveD, new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y))))
	nx := mod(new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x)))
	ny := mod(new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x)))
	dx := new(big.Int).ModInverse(mod(new(big.Int).Add(big.NewInt(1), prod)), field)
	dy := new(big.Int).ModInverse(mod(new(big.Int).Sub(big.NewInt(1), prod)), field)
	return point{mod(new(big.Int).Mul(nx, dx)), mod(new(big.Int).Mul(ny, dy))}
}
func mulTest(p point, n *big.Int) point {
	out := point{big.NewInt(0), big.NewInt(1)}
	for i := n.BitLen() - 1; i >= 0; i-- {
		out = addTest(out, out)
		if n.Bit(i) == 1 {
			out = addTest(out, p)
		}
	}
	return out
}
func leTest(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
func encodeTest(p point) []byte { out := leTest(p.y); out[31] |= byte(p.x.Bit(0) << 7); return out }
func sameTest(a, b point) bool  { return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 }
func baseTest(t *testing.T) point {
	t.Helper()
	b := bytes.Repeat([]byte{0x66}, 32)
	b[0] = 0x58
	p, ok := decode(b)
	if !ok {
		t.Fatal("base decode")
	}
	return p
}
func TestAllEightTorsionPointsRejected(t *testing.T) {
	// Project a deterministic arbitrary curve point by L onto its torsion group,
	// choose exact order 8 and enumerate every point (including identity).
	var torsion point
	found := false
	for y := int64(2); y < 100; y++ {
		p, ok := decode(leTest(big.NewInt(y)))
		if !ok {
			continue
		}
		candidate := mulTest(p, order)
		if !smallOrder(candidate) {
			t.Fatal("L projection not torsion")
		}
		four := mulTest(candidate, big.NewInt(4))
		if four.x.Sign() != 0 || four.y.Cmp(big.NewInt(1)) != 0 {
			torsion = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no order-eight fixture")
	}
	seed := bytes.Repeat([]byte{7}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	message := []byte("TEST ONLY torsion")
	signature := ed25519.Sign(private, message)
	point := point{big.NewInt(0), big.NewInt(1)}
	seen := map[string]bool{}
	for n := 0; n < 8; n++ {
		encoded := encodeTest(point)
		if seen[string(encoded)] {
			t.Fatal("torsion enumeration repeated")
		}
		seen[string(encoded)] = true
		decoded, ok := decode(encoded)
		if !ok || !smallOrder(decoded) {
			t.Fatal(n, "canonical torsion precheck")
		}
		if err := Verify(context.Background(), encoded, message, signature); err != ErrInvalid {
			t.Fatal(n, "torsion public key accepted", err)
		}
		changed := bytes.Clone(signature)
		copy(changed[:32], encoded)
		if err := Verify(context.Background(), public, message, changed); err != ErrInvalid {
			t.Fatal(n, "torsion R accepted", err)
		}
		point = addTest(point, torsion)
	}
}
func TestCofactorOnlyAcceptanceIsRejected(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	aPoint, ok := decode(public)
	if !ok {
		t.Fatal("public decode")
	}
	expanded := sha512.Sum512(seed)
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	aScalar := littleEndian(expanded[:32])
	nonce := big.NewInt(123)
	rPrime := mulTest(baseTest(t), nonce)
	orderTwo := point{big.NewInt(0), new(big.Int).Sub(field, big.NewInt(1))}
	mixedR := addTest(rPrime, orderTwo)
	rBytes := encodeTest(mixedR)
	message := []byte("TEST ONLY cofactor residual")
	hash := sha512.New()
	hash.Write(rBytes)
	hash.Write(public)
	hash.Write(message)
	challenge := new(big.Int).Mod(littleEndian(hash.Sum(nil)), order)
	s := new(big.Int).Mod(new(big.Int).Add(nonce, new(big.Int).Mul(challenge, aScalar)), order)
	sig := append(rBytes, leTest(s)...)
	lhs := mulTest(baseTest(t), s)
	rhs := addTest(mixedR, mulTest(aPoint, challenge))
	if sameTest(lhs, rhs) || !sameTest(mulTest(lhs, big.NewInt(8)), mulTest(rhs, big.NewInt(8))) {
		t.Fatal("fixture does not separate equations")
	}
	if smallOrder(aPoint) || smallOrder(mixedR) {
		t.Fatal("fixture rejected for torsion-only input rather than equation")
	}
	if err := Verify(context.Background(), public, message, sig); err != ErrInvalid {
		t.Fatal("cofactor-only signature accepted", err)
	}
}
func TestCanonicalPointDecoderAndStandardPositiveSignatures(t *testing.T) {
	for _, raw := range [][]byte{leTest(field), leTest(new(big.Int).Add(field, big.NewInt(1)))} {
		if _, ok := decode(raw); ok {
			t.Fatal("noncanonical y accepted")
		}
	}
	negativeZero := leTest(big.NewInt(1))
	negativeZero[31] = 128
	if _, ok := decode(negativeZero); ok {
		t.Fatal("negative zero accepted")
	}
	offCurve := false
	for y := int64(2); y < 100; y++ {
		raw := leTest(big.NewInt(y))
		if _, ok := decode(raw); !ok {
			offCurve = true
			break
		}
	}
	if !offCurve {
		t.Fatal("off-curve fixtures absent")
	}
	for i := byte(0); i < 32; i++ {
		seed := bytes.Repeat([]byte{i}, 32)
		private := ed25519.NewKeyFromSeed(seed)
		public := private.Public().(ed25519.PublicKey)
		message := []byte{0, 255, i}
		sig := ed25519.Sign(private, message)
		if err := Verify(context.Background(), public, message, sig); err != nil {
			t.Fatal(hex.EncodeToString(public), err)
		}
	}
}

func FuzzStrictPublicInputs(f *testing.F) {
	seed := bytes.Repeat([]byte{3}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	key := private.Public().(ed25519.PublicKey)
	message := []byte("TEST ONLY public input fuzz")
	signature := ed25519.Sign(private, message)
	f.Add([]byte(key), message, signature)
	f.Add(make([]byte, 32), []byte{}, make([]byte, 64))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, key, message, signature []byte) {
		if len(message) > 4096 {
			return
		}
		err := Verify(context.Background(), key, message, signature)
		if err == nil {
			a, ok := decode(key)
			if !ok || smallOrder(a) {
				t.Fatal("accepted unsafe public key")
			}
			r, ok := decode(signature[:32])
			if !ok || smallOrder(r) {
				t.Fatal("accepted unsafe R")
			}
			if littleEndian(signature[32:]).Cmp(order) >= 0 {
				t.Fatal("accepted unsafe scalar")
			}
		} else if err != ErrInvalid {
			t.Fatal(err)
		}
	})
}
