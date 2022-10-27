package edwards448

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	// TODO: optimize
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
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	// TODO: optimize
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

// VarTimeDoubleScalarBaseMult sets v = a * A + b * B, where B is the canonical
// generator, and returns v.
//
// Execution time depends on the inputs.
func (v *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {
	// TODO: optimize
	aa := new(Point).ScalarMult(a, A)
	bb := new(Point).ScalarBaseMult(b)
	v.Add(aa, bb)
	return v
}
