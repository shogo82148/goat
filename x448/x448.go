package x448

import (
	"github.com/shogo82148/goat/internal/curve448/fe"
)

func X448(scalar, point []byte) ([]byte, error) {
	var k [56]byte
	copy(k[:], scalar)
	k[0] &= 252
	k[55] |= 128

	var u fe.Element
	u.SetBytes(point)

	var x1, x2, z2, x3, z3 fe.Element
	x1.Set(&u)
	x2.One()
	x3.Set(&u)
	z3.One()
	swap := 0

	for t := 56*8 - 1; t >= 0; t-- {
		kt := int(k[t/8]>>(t%8)) & 1
		swap ^= kt
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = kt

		var a, aa, b, bb, e, c, d, da, cb fe.Element
		a.Add(&x2, &z2)
		aa.Square(&a)
		b.Sub(&x2, &z2)
		bb.Square(&b)
		e.Sub(&aa, &bb)
		c.Add(&x3, &z3)
		d.Sub(&x3, &z3)
		da.Mul(&d, &a)
		cb.Mul(&c, &b)

		x3.Add(&da, &cb)
		x3.Square(&x3)

		z3.Sub(&da, &cb)
		z3.Square(&z3)
		z3.Mul(&z3, &x1)

		x2.Mul(&aa, &bb)

		z2.Mul32(&e, 39081)
		z2.Add(&z2, &aa)
		z2.Mul(&z2, &e)
	}

	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	var ret fe.Element
	ret.Mul(&x2, ret.Inv(&z2))
	return ret.Bytes(), nil
}
