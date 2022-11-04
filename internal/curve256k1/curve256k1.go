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

func (p *PointJacobian) Zero() *PointJacobian {
	p.x.Zero()
	p.y.Zero()
	p.z.One()
	return p
}

func (p *PointJacobian) Set(v *PointJacobian) *PointJacobian {
	p.x.Set(&v.x)
	p.y.Set(&v.y)
	p.z.Set(&v.z)
	return p
}

func (p *PointJacobian) Select(a, b *PointJacobian, cond int) *PointJacobian {
	p.x.Select(&a.x, &b.x, cond)
	p.y.Select(&a.y, &b.y, cond)
	p.z.Select(&a.z, &b.z, cond)
	return p
}

func (p *PointJacobian) Neg(v *PointJacobian) *PointJacobian {
	p.x.Neg(&v.x)
	p.y.Set(&v.y)
	p.z.Set(&v.z)
	return p
}

func (p *PointJacobian) CondNeg(cond int) *PointJacobian {
	var neg PointJacobian
	neg.Neg(p)
	return p.Select(&neg, p, cond)
}

// FromAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func (p *PointJacobian) FromAffine(v *Point) *PointJacobian {
	p.x.Set(&v.x)
	p.y.Set(&v.y)
	p.z.Select(&feZero, &feOne, v.x.IsZero()|v.y.IsZero())
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

func (p *Point) ToBig(x, y *big.Int) (xx, yy *big.Int) {
	x.SetBytes(p.x.Bytes())
	y.SetBytes(p.y.Bytes())
	return x, y
}

// Add set p = a + b.
func (p *PointJacobian) Add(a, b *PointJacobian) *PointJacobian {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl

	var z1z1, z2z2, u1, u2, s1, s2, tmp field.Element
	var h, i, j, r, v, x3, y3, z3 field.Element

	// Z1Z1 = Z1^2
	z1z1.Square(&a.z)

	// Z2Z2 = Z2^2
	z2z2.Square(&b.z)

	// U1 = X1*Z2Z2
	u1.Mul(&a.x, &z2z2)

	// U2 = X2*Z1Z1
	u2.Mul(&b.x, &z1z1)

	// S1 = Y1*Z2*Z2Z2
	s1.Mul(&a.y, &b.z)
	s1.Mul(&s1, &z2z2)

	// S2 = Y2*Z1*Z1Z1
	s2.Mul(&b.y, &a.z)
	s2.Mul(&s2, &z1z1)

	// H = U2-U1
	h.Sub(&u2, &u1)

	// I = (2*H)^2
	i.Add(&h, &h)
	i.Square(&i)

	// J = H*I
	j.Mul(&h, &i)

	// r = 2*(S2-S1)
	r.Sub(&s2, &s1)
	r.Add(&r, &r)

	// V = U1*I
	v.Mul(&u1, &i)

	// X3 = r^2-J-2*V
	x3.Square(&r)
	x3.Sub(&x3, &j)
	tmp.Add(&v, &v)
	x3.Sub(&x3, &tmp)

	// Y3 = r*(V-X3)-2*S1*J
	y3.Sub(&v, &x3)
	y3.Mul(&y3, &r)
	tmp.Mul(&s1, &j)
	tmp.Add(&tmp, &tmp)
	y3.Sub(&y3, &tmp)

	// Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
	z3.Add(&a.z, &b.z)
	z3.Square(&z3)
	z3.Sub(&z3, &z1z1)
	z3.Sub(&z3, &z2z2)
	z3.Mul(&z3, &h)

	var zero int
	zero = b.z.IsZero()
	x3.Select(&a.x, &x3, zero)
	y3.Select(&a.y, &y3, zero)
	z3.Select(&a.z, &z3, zero)

	zero = a.z.IsZero()
	x3.Select(&b.x, &x3, zero)
	y3.Select(&b.y, &y3, zero)
	z3.Select(&b.z, &z3, zero)

	p.x.Set(&x3)
	p.y.Set(&y3)
	p.z.Set(&z3)
	return p
}

// Add set p = a + a.
func (p *PointJacobian) Double(v *PointJacobian) *PointJacobian {
	// see http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

	var a, b, c, d, e, f, tmp, x3, y3, z3 field.Element

	// A = X1^2
	a.Square(&v.x)

	// B = Y1^2
	b.Square(&v.y)

	// C = B^2
	c.Square(&b)

	// D = 2*((X1+B)^2-A-C)
	d.Add(&v.x, &b)
	d.Square(&d)
	d.Sub(&d, &a)
	d.Sub(&d, &c)
	d.Add(&d, &d)

	// E = 3*A
	e.Add(&a, &a)
	e.Add(&e, &a)

	// F = E^2
	f.Square(&e)

	// X3 = F-2*D
	x3.Add(&d, &d)
	x3.Sub(&f, &x3)

	// Y3 = E*(D-X3)-8*C
	tmp.Add(&c, &c)
	tmp.Add(&tmp, &tmp)
	tmp.Add(&tmp, &tmp)
	y3.Sub(&d, &x3)
	y3.Mul(&e, &y3)
	y3.Sub(&y3, &tmp)

	// Z3 = 2*Y1*Z1
	z3.Mul(&v.y, &v.z)
	z3.Add(&z3, &z3)

	zero := v.z.Equal(&feZero)
	p.x.Select(&v.x, &x3, zero)
	p.y.Select(&v.y, &y3, zero)
	p.z.Select(&v.z, &z3, zero)
	return p
}

func (p *PointJacobian) ScalarMult(q *PointJacobian, k []byte) *PointJacobian {
	var zero PointJacobian
	zero.Zero()
	p.Zero()
	for i := len(k) - 1; i >= 0; i-- {
		b := k[i]
		for j := 7; j >= 0; j-- {
			var tmp PointJacobian
			p.Double(p)
			tmp.Select(q, &zero, int(b>>j)&1)
			p.Add(p, &tmp)
		}
	}
	return p
}
