package curve256k1

import "crypto/subtle"

type lookupTable struct {
	points [8]PointJacobian
}

func (v *lookupTable) Init(p *PointJacobian) {
	// Goal: v.points[i] = (i+1)*Q, i.e., Q, 2Q, ..., 8Q
	// This allows lookup of -8Q, ..., -Q, 0, Q, ..., 8Q
	points := &v.points
	points[0].Set(p)
	for i := 1; i < 8; i++ {
		var v PointJacobian
		points[i].Set(v.Add(&points[i-1], p))
	}
}

func (v *lookupTable) SelectInto(dest *PointJacobian, x int8) {
	// Compute xabs = |x|
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	dest.Zero()
	for i := 1; i <= 8; i++ {
		// Set dest = i*Q if |x| = i
		cond := subtle.ConstantTimeByteEq(xabs, uint8(i))
		dest.Select(&v.points[i-1], dest, cond)
	}
	// Now dest = |x|*Q, conditionally negate to get x*Q
	dest.CondNeg(int(xmask & 1))
}
