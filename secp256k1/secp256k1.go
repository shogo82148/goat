// Package secp256k1 implements the standard secp256k1 elliptic curve over prime fields.
package secp256k1

// based on https://tech.ginco.io/post/secp256k1-golang-implementation/
// https://github.com/GincoInc/go-crypto/blob/f40651045f442b48b7b70e835532df09b4e2ecfa/secp256k1.go

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"sync"

	"github.com/shogo82148/goat/internal/curve256k1"
)

var paramN = [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}

// PrivateKey represents a secp256k1 private key.
type PrivateKey struct {
	d [32]byte
}

// GenerateKey generates a new private key.
func GenerateKey() *PrivateKey {
	for {
		var buf [32]byte
		rand.Read(buf[:])
		if !isZero(&buf) && !overflow(&buf) {
			return &PrivateKey{d: buf}
		}
	}
}

func isZero(buf *[32]byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

func overflow(buf *[32]byte) bool {
	return bytes.Compare(buf[:], paramN[:]) >= 0
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv.d[:], xx.d[:]) == 1
}

// Public returns the corresponding public key.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.PublicKey()
}

// PublicKey returns the corresponding public key.
func (key *PrivateKey) PublicKey() *PublicKey {
	var ret curve256k1.Point
	var retj curve256k1.PointJacobian
	retj.ScalarBaseMult(key.d[:])
	ret.FromJacobian(&retj)
	return &PublicKey{p: ret}
}

// PublicKey represents a secp256k1 public key.
type PublicKey struct {
	p curve256k1.Point
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.p.Equal(&xx.p) == 1
}

var initonce sync.Once
var curve secp256k1

func initCurve() {
	// SEC 2 (Draft) Ver. 2.0 2.4 Recommended 256-bit Elliptic Curve Domain Parameters over Fp
	// http://www.secg.org/sec2-v2.pdf
	curve.params = &elliptic.CurveParams{
		Name:    "secp256k1",
		BitSize: 256,
		P:       bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
		N:       bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
		B:       bigHex("0000000000000000000000000000000000000000000000000000000000000007"),
		Gx:      bigHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
		Gy:      bigHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
	}
}

func bigHex(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("secp256k1: failed to parse hex")
	}
	return i
}

// Curve returns the standard secp256k1 elliptic curve.
//
// Multiple invocations of this function will return the same value, so it can be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Curve() elliptic.Curve {
	initonce.Do(initCurve)
	return &curve
}

var _ elliptic.Curve = (*secp256k1)(nil)

type secp256k1 struct {
	params *elliptic.CurveParams
}

// Params returns the parameters for the curve.
func (crv *secp256k1) Params() *elliptic.CurveParams {
	return crv.params
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (crv *secp256k1) IsOnCurve(x, y *big.Int) bool {
	var p curve256k1.Point
	if _, err := p.NewPoint(x, y); err != nil {
		return false
	}
	return curve256k1.IsOnCurve(&p)
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (crv *secp256k1) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var p1, p2, p3 curve256k1.Point
	var pj1, pj2, pj3 curve256k1.PointJacobian
	if _, err := p1.NewPoint(x1, y1); err != nil {
		panic("invalid point")
	}
	if _, err := p2.NewPoint(x2, y2); err != nil {
		panic("invalid point")
	}
	pj1.FromAffine(&p1)
	pj2.FromAffine(&p2)
	pj3.Add(&pj1, &pj2)
	p3.FromJacobian(&pj3)
	return p3.ToBig(new(big.Int), new(big.Int))
}

// Double returns 2*(x,y)
func (crv *secp256k1) Double(x1, y1 *big.Int) (x, y *big.Int) {
	var p1, p3 curve256k1.Point
	var pj1, pj3 curve256k1.PointJacobian
	if _, err := p1.NewPoint(x1, y1); err != nil {
		panic("invalid point")
	}
	pj1.FromAffine(&p1)
	pj3.Double(&pj1)
	p3.FromJacobian(&pj3)
	return p3.ToBig(new(big.Int), new(big.Int))
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (crv *secp256k1) ScalarMult(Bx, By *big.Int, k []byte) (x, y *big.Int) {
	var B, ret curve256k1.Point
	var Bj, retj curve256k1.PointJacobian
	if _, err := B.NewPoint(Bx, By); err != nil {
		panic("invalid point")
	}
	Bj.FromAffine(&B)
	retj.ScalarMult(&Bj, k)
	ret.FromJacobian(&retj)
	return ret.ToBig(new(big.Int), new(big.Int))
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (crv *secp256k1) ScalarBaseMult(k []byte) (x, y *big.Int) {
	var ret curve256k1.Point
	var retj curve256k1.PointJacobian
	retj.ScalarBaseMult(k)
	ret.FromJacobian(&retj)
	return ret.ToBig(new(big.Int), new(big.Int))
}

// CombinedMult returns [s1]G + [s2]P where G is the generator.
// It's used through an interface upgrade in crypto/ecdsa.
func (crv *secp256k1) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
	// calculate [s1]G
	var retj1 curve256k1.PointJacobian
	retj1.ScalarBaseMult(s1)

	var B curve256k1.Point
	var Bj, retj2 curve256k1.PointJacobian
	if _, err := B.NewPoint(Px, Py); err != nil {
		panic("invalid point")
	}

	// calculate [s2]P
	Bj.FromAffine(&B)
	retj2.ScalarMult(&Bj, s2)

	// add them
	var ret curve256k1.Point
	retj1.Add(&retj1, &retj2)
	ret.FromJacobian(&retj1)
	return ret.ToBig(new(big.Int), new(big.Int))
}
