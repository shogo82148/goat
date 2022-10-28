package edwards448

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	table := basepointTable()

	// Write x = sum(x_i * 16^i) so  x*B = sum( B*x_i*16^i )
	//
	// Group even and odd coefficients
	// x*B     = x_0*16^0*B + x_2*16^2*B + ... + x_110*16^110*B
	//         + x_1*16^1*B + x_3*16^3*B + ... + x_111*16^111*B
	// x*B     = x_0*16^0*B + x_2*16^2*B + ... + x_110*16^110*B
	//    + 16*( x_1*16^0*B + x_3*16^2*B + ... + x_111*16^110*B)
	//
	// We use a lookup table for each i to get x_i*16^(2*i)*B
	// and do four doublings to multiply by 16.
	digits := x.signedRadix16()
	v.Set(NewIdentityPoint())

	// Accumulate the odd components first
	for i := 1; i < 112; i += 2 {
		var multiple Point
		table[i/2].SelectInto(&multiple, digits[i])
		v.Add(v, &multiple)
	}

	// Multiply by 16
	v.Add(v, v) // * 2
	v.Add(v, v) // * 4
	v.Add(v, v) // * 8
	v.Add(v, v) // * 16

	// Accumulate the even components first
	for i := 0; i < 112; i += 2 {
		var multiple Point
		table[i/2].SelectInto(&multiple, digits[i])
		v.Add(v, &multiple)
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
