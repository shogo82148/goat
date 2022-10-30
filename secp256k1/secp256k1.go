package secp256k1

// based on https://tech.ginco.io/post/secp256k1-golang-implementation/
// https://github.com/GincoInc/go-crypto/blob/master/secp256k1.go

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/shogo82148/goat/internal/secp256k1/field"
)

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

var feZero field.Element
var fe7 field.Element

func init() {
	fe7.SetBytes([]byte{0x07})
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (crv *secp256k1) IsOnCurve(x, y *big.Int) bool {
	var X, Y field.Element
	if err := X.SetBytes(x.Bytes()); err != nil {
		return false
	}
	if err := Y.SetBytes(y.Bytes()); err != nil {
		return false
	}

	// x^3
	var x3 field.Element
	x3.Square(&X)
	x3.Mul(&x3, &X)

	// y^2
	var y2 field.Element
	y2.Square(&Y)

	// x^3 - y^2 + 7
	var ret field.Element
	ret.Sub(&x3, &y2)
	ret.Add(&ret, &fe7)

	return ret.Equal(&feZero) == 1
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}

	return z
}

// affineFromJacobian reverses the Jacobian transform. If the point is ∞ it returns 0, 0.
func (crv *secp256k1) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, crv.params.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, crv.params.P)

	zinvsq.Mul(zinvsq, zinv)

	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, crv.params.P)

	return
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and (x2, y2, z2) and returns their sum, also in Jacobian form.
func (crv *secp256k1) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, crv.params.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, crv.params.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, crv.params.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, crv.params.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, crv.params.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, crv.params.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, crv.params.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, crv.params.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, crv.params.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, crv.params.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, crv.params.P)

	return x3, y3, z3
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (crv *secp256k1) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(crv.addJacobian(x1, y1, z1, x2, y2, z2))
}

// Double returns 2*(x,y)
func (crv *secp256k1) Double(x1, y1 *big.Int) (x, y *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and returns its double, also in Jacobian form.
func (crv *secp256k1) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	a := new(big.Int).Mul(x, x)
	b := new(big.Int).Mul(y, y)
	c := new(big.Int).Mul(b, b)

	d := new(big.Int).Add(x, b)
	d.Mul(d, d)
	d.Sub(d, a)
	d.Sub(d, c)
	d.Mul(d, big.NewInt(2))

	e := new(big.Int).Mul(big.NewInt(3), a)
	f := new(big.Int).Mul(e, e)

	x3 := new(big.Int).Mul(big.NewInt(2), d)
	x3.Sub(f, x3)
	x3.Mod(x3, crv.params.P)

	y3 := new(big.Int).Sub(d, x3)
	y3.Mul(e, y3)
	y3.Sub(y3, new(big.Int).Mul(big.NewInt(8), c))
	y3.Mod(y3, crv.params.P)

	z3 := new(big.Int).Mul(y, z)
	z3.Mul(big.NewInt(2), z3)
	z3.Mod(z3, crv.params.P)

	return x3, y3, z3
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (crv *secp256k1) ScalarMult(Bx, By *big.Int, k []byte) (x, y *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = crv.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = crv.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (crv *secp256k1) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(crv.params.Gx, crv.params.Gy, k)
}
