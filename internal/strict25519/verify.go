// SPDX-License-Identifier: Apache-2.0
// Package strict25519 enforces Package 2.0's public verification rules before
// Go's RFC8032 Ed25519 primitive checks the uncofactored group equation. Go's
// supported minimum (1.23) and current primitive compare the canonical R of
// [S]B - [k]A directly; no multiplication by the cofactor is used.
// This variable-time field arithmetic handles PUBLIC points only. Private key
// operations belong to the explicit Host Signer, never these helpers.
package strict25519

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/big"
)

var ErrInvalid = errors.New("invalid strict Ed25519 signature")
var field = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
var order = mustInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
var curveD = mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), field)))
var sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(field, big.NewInt(1)), 2), field)
var rootExponent = new(big.Int).Rsh(new(big.Int).Add(field, big.NewInt(3)), 3)

func mustInteger(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid curve constant")
	}
	return n
}
func mod(n *big.Int) *big.Int { return new(big.Int).Mod(n, field) }
func littleEndian(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

type point struct{ x, y *big.Int }

// RFC8032 5.1.3: reject y>=p, off-curve values and the negative encoding of x=0.
func decode(b []byte) (point, bool) {
	if len(b) != 32 {
		return point{}, false
	}
	raw := append([]byte{}, b...)
	sign := uint(raw[31] >> 7)
	raw[31] &= 127
	y := littleEndian(raw)
	if y.Cmp(field) >= 0 {
		return point{}, false
	}
	y2 := mod(new(big.Int).Mul(y, y))
	numerator := mod(new(big.Int).Sub(y2, big.NewInt(1)))
	denominator := mod(new(big.Int).Add(new(big.Int).Mul(curveD, y2), big.NewInt(1)))
	inverse := new(big.Int).ModInverse(denominator, field)
	if inverse == nil {
		return point{}, false
	}
	x2 := mod(new(big.Int).Mul(numerator, inverse))
	x := new(big.Int).Exp(x2, rootExponent, field)
	if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		x = mod(new(big.Int).Mul(x, sqrtM1))
	}
	if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		return point{}, false
	}
	if x.Sign() == 0 && sign != 0 {
		return point{}, false
	}
	if x.Bit(0) != sign {
		x = new(big.Int).Sub(field, x)
	}
	return point{x, y}, true
}
func double(p point) (point, bool) {
	x2 := mod(new(big.Int).Mul(p.x, p.x))
	y2 := mod(new(big.Int).Mul(p.y, p.y))
	product := mod(new(big.Int).Mul(curveD, new(big.Int).Mul(x2, y2)))
	ix := new(big.Int).ModInverse(mod(new(big.Int).Add(big.NewInt(1), product)), field)
	iy := new(big.Int).ModInverse(mod(new(big.Int).Sub(big.NewInt(1), product)), field)
	if ix == nil || iy == nil {
		return point{}, false
	}
	x := mod(new(big.Int).Mul(new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(p.x, p.y)), ix))
	y := mod(new(big.Int).Mul(new(big.Int).Add(y2, x2), iy))
	return point{x, y}, true
}
func smallOrder(p point) bool {
	for i := 0; i < 3; i++ {
		var ok bool
		p, ok = double(p)
		if !ok {
			return true
		}
	}
	return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0
}
func Verify(ctx context.Context, key, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) != 32 || len(signature) != 64 {
		return ErrInvalid
	}
	a, ok := decode(key)
	if !ok || smallOrder(a) {
		return ErrInvalid
	}
	r, ok := decode(signature[:32])
	if !ok || smallOrder(r) {
		return ErrInvalid
	}
	if littleEndian(signature[32:]).Cmp(order) >= 0 {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	valid := ed25519.Verify(ed25519.PublicKey(key), message, signature)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !valid {
		return ErrInvalid
	}
	return nil
}

func CheckPublicKey(ctx context.Context, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, ok := decode(key)
	if !ok || smallOrder(p) {
		return ErrInvalid
	}
	return ctx.Err()
}
