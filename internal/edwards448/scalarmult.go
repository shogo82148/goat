package edwards448

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
//
// TODO: The scalar multiplication is done in constant time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	zero := new(Point).Zero()
	tmp := new(Point).Set(NewGeneratorPoint())
	v.Set(NewIdentityPoint())
	bytes := x.bytes()
	for _, b := range bytes {
		for i := 0; i < 8; i++ {
			var tmp2 Point
			tmp2.Select(tmp, zero, int(b>>i)&1)
			v.Add(v, &tmp2)
			tmp.Double(tmp)
		}
	}
	return v
}

// ScalarMult sets v = x * q, and returns v.
//
// TODO: The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	return v
}
