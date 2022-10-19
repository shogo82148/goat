package edwards448

import fe "github.com/shogo82148/goat/internal/edwards448/field"

// Point types.

type projP1xP1 struct {
	X, Y, Z, T fe.Element
}

type projP2 struct {
	X, Y, Z fe.Element
}

// Point represents a point on the edwards25519 curve.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is NOT valid, and it may be used only as a receiver.
type Point struct {
	// The point is internally represented in extended coordinates (X, Y, Z, T)
	// where x = X/Z, y = Y/Z, and xy = T/Z per https://eprint.iacr.org/2008/522.
	x, y, z, t fe.Element

	// Make the type not comparable (i.e. used with == or as a map key), as
	// equivalent points can be represented by different Go values.
	_ incomparable
}

type incomparable [0]func()

func (v *projP2) Zero() *projP2 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	*v = *u
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
	// TODO:
	// checkInitialized(v)

	var zInv, x, y fe.Element
	zInv.Inv(&v.z)     // zInv = 1 / Z
	x.Mul(&v.x, &zInv) // x = X / Z
	y.Mul(&v.y, &zInv) // y = Y / Z

	out := copyFieldElement(buf, &y)
	out[56] |= byte(x.IsNegative() << 7)
	return out
}

func (v *Point) SetBytes(data []byte) (*Point, error) {
	// y := new(fe.Element).SetBytes(data[:56])

	// x^2 = (y^2 - 1) / (d y^2 - 1) (mod p)
	return v, nil
}

// Conversions.

func (v *projP2) FromP1xP1(p *projP1xP1) *projP2 {
	v.X.Mul(&p.X, &p.T)
	v.Y.Mul(&p.Y, &p.Z)
	v.Z.Mul(&p.Z, &p.T)
	return v
}

func copyFieldElement(buf *[57]byte, v *fe.Element) []byte {
	copy(buf[:], v.Bytes())
	return buf[:]
}
