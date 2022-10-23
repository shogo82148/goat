package edwards448

import (
	"errors"

	"github.com/shogo82148/goat/internal/edwards448/field"
)

var feOne, feD field.Element

func init() {
	feOne.One()

	// D
	d := [56]byte{
		0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	feD.SetBytes(d[:])
}

// Point represents a point on the edwards25519 curve.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is NOT valid, and it may be used only as a receiver.
type Point struct {
	// The point is internally represented in extended coordinates (X, Y, Z)
	// where x = X/Z, y = Y/Z.
	x, y, z field.Element

	// Make the type not comparable (i.e. used with == or as a map key), as
	// equivalent points can be represented by different Go values.
	_ incomparable
}

type incomparable [0]func()

func checkInitialized(points ...*Point) {
	for _, p := range points {
		if p.x == (field.Element{}) && p.y == (field.Element{}) {
			panic("edwards25519: use of uninitialized Point")
		}
	}
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	*v = *u
	return v
}

func (v *Point) Zero() *Point {
	v.x.Zero()
	v.y.One()
	v.z.One()
	return v
}

// Encoding.

// Bytes returns the canonical 32-byte encoding of v, according to RFC 8032,
// Section 5.2.2.
func (v *Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var buf [57]byte
	return v.bytes(&buf)
}

func (v *Point) bytes(buf *[57]byte) []byte {
	checkInitialized(v)

	var zInv, x, y field.Element
	zInv.Inv(&v.z)     // zInv = 1 / Z
	x.Mul(&v.x, &zInv) // x = X / Z
	y.Mul(&v.y, &zInv) // y = Y / Z

	out := copyFieldElement(buf, &y)
	out[56] |= byte(v.x.IsNegative() << 7)
	return out
}

func (v *Point) SetBytes(data []byte) (*Point, error) {
	if len(data) != 57 {
		return nil, errors.New("edwards448: invalid point encoding length")
	}

	var y field.Element
	y.SetBytes(data[:56])

	// -x² + y² = 1 + dx²y²
	// x² + dx²y² = x²(dy² + 1) = y² - 1
	// x² = (y² - 1) / (dy² + 1)

	// u = y² - 1
	var u, y2 field.Element
	y2.Square(&y)
	u.Sub(&feOne, &y2)

	// v = dy² + 1
	var vv field.Element
	vv.Mul(&y2, &feD)
	vv.Add(&vv, &feOne)

	// x = +√(u/v)
	var x field.Element
	_, wasSquare := x.SqrtRatio(&u, &vv)

	// Select the negative square root if the sign bit is set.
	var xNeg field.Element
	xNeg.Negate(&x)
	x.Select(&xNeg, &x, int(data[56]>>7))

	if wasSquare == 0 {
		return nil, errors.New("edwards448: invalid point encoding")
	}

	v.x.Set(&x)
	v.y.Set(&y)
	v.z.One()
	return v, nil
}

// Conversions.

func copyFieldElement(buf *[57]byte, v *field.Element) []byte {
	copy(buf[:56], v.Bytes())
	return buf[:]
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	checkInitialized(v, u)

	var x1, y1, x2, y2 field.Element
	x1.Mul(&v.x, &u.z)
	y1.Mul(&v.y, &u.z)
	x2.Mul(&u.x, &v.z)
	y2.Mul(&u.y, &v.z)
	return x1.Equal(&x2) & y1.Equal(&y2)
}

func (v *Point) Add(p, q *Point) *Point {
	checkInitialized(p, q)

	var a, b, c, d, e, f, g, h, x, y, z field.Element
	var tmp1, tmp2 field.Element

	// A = Z1*Z2
	a.Mul(&p.z, &q.z)

	// B = A^2
	b.Square(&a)

	// C = X1*X2
	c.Mul(&p.x, &q.x)

	// D = Y1*Y2
	d.Mul(&p.y, &q.y)

	// E = d*C*D
	tmp1.Mul(&feD, &c)
	e.Mul(&tmp1, &d)

	// F = B-E
	f.Sub(&b, &e)

	// G = B+E
	g.Add(&b, &e)

	// H = (X1+Y1)*(X2+Y2)
	tmp1.Add(&p.x, &p.y)
	tmp2.Add(&q.x, &q.y)
	h.Mul(&tmp1, &tmp2)

	// X3 = A*F*(H-C-D)
	x.Sub(&h, &c)
	x.Sub(&x, &d)
	x.Mul(&x, &a)
	x.Mul(&x, &f)

	// Y3 = A*G*(D-C)
	y.Sub(&d, &c)
	y.Mul(&y, &g)
	y.Mul(&y, &a)

	// Z3 = F*G
	z.Mul(&f, &g)

	v.x.Set(&x)
	v.y.Set(&y)
	v.z.Set(&z)
	return v
}
