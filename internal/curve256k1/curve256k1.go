package curve256k1

import (
	"errors"
	"math/big"

	"github.com/shogo82148/goat/internal/curve256k1/field"
)

type Point struct {
	x, y field.Element
}

var feZero, feOne field.Element
var fe7 field.Element

func init() {
	feOne.One()
	if err := fe7.SetBytes([]byte{0x07}); err != nil {
		panic(err)
	}
}

func (p *Point) NewPoint(x, y *big.Int) (*Point, error) {
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}
	if x.BitLen() > 256 || y.BitLen() > 256 {
		return nil, errors.New("overflowing coordinate")
	}
	var buf [32]byte
	x.FillBytes(buf[:])
	if err := p.x.SetBytes(buf[:]); err != nil {
		return nil, err
	}
	y.FillBytes(buf[:])
	if err := p.y.SetBytes(buf[:]); err != nil {
		return nil, err
	}
	return p, nil
}

func IsOnCurve(p *Point) bool {
	// x^3
	var x3 field.Element
	x3.Square(&p.x)
	x3.Mul(&x3, &p.x)

	// y^2
	var y2 field.Element
	y2.Square(&p.y)

	// x^3 - y^2 + 7
	var ret field.Element
	ret.Sub(&x3, &y2)
	ret.Add(&ret, &fe7)

	return ret.Equal(&feZero) == 1
}

type PointJacobian struct {
	// X = x/z^2, Y = y/z^3
	x, y, z field.Element
}

// FromAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func (p *PointJacobian) FromAffine(v *Point) *PointJacobian {
	p.x.Set(&v.x)
	p.y.Set(&v.y)
	p.z.Select(&feZero, &feOne, v.x.Equal(&feZero)|v.y.Equal(&feZero))
	return p
}

// ToAffine reverses the Jacobian transform. If the point is ∞ it returns 0, 0.
func (p *Point) ToAffine(v *PointJacobian) *Point {
	if v.z.Equal(&feZero) == 1 {
		p.x.Zero()
		p.y.Zero()
		return p
	}

	var zinv field.Element // = 1/z mod p
	zinv.Inv(&v.z)

	var zinvsq, zinvcb field.Element // 1/z^2, 1/z^3
	zinvsq.Square(&zinv)
	zinvcb.Mul(&zinv, &zinvsq)

	p.x.Mul(&v.x, &zinvsq)
	p.y.Mul(&v.y, &zinvcb)
	return p
}

// Add set p = a + b.
func (p *PointJacobian) Add(a, b *PointJacobian) *PointJacobian {
	// var z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, x3, y3, z3 field.Element

	// z1z1.Square(&a.z)
	// z2z2.Square(&b.z)
	// u1.Mul(&a.x, &z2z2)
	// u2.Mul(&b.x, &z1z1)
	// s1.Mul(&a)
	return p
}
