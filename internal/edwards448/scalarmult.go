package edwards448

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
//
// TODO: The scalar multiplication is done in constant time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	tmp := new(Point).Set(NewGeneratorPoint())
	v.Set(NewIdentityPoint())
	bytes := x.Bytes()
	for i := 56*8 - 1; i >= 0; i-- {
		v.Double(v)
		b := (bytes[i/8] >> (i % 8)) & 1
		if b != 0 {
			v.Add(v, tmp)
		}
	}
	return v
}

// ScalarMult sets v = x * q, and returns v.
//
// TODO: The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	v.Set(NewIdentityPoint())
	bytes := x.Bytes()
	for i := 56*8 - 1; i >= 0; i-- {
		v.Double(v)
		b := (bytes[i/8] >> (i % 8)) & 1
		if b != 0 {
			v.Add(v, q)
		}
	}
	return v
}
