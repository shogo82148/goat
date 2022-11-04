package curve256k1

import (
	"crypto/subtle"
	"strconv"
)

type lookupTable struct {
	points [16]PointJacobian
}

func (v *lookupTable) Init(p *PointJacobian) {
	points := &v.points
	points[0].Set(p)
	for i := 1; i < 16; i++ {
		var v PointJacobian
		points[i].Set(v.Add(&points[i-1], p))
	}
}

// x must be in [0, 15].
func (v *lookupTable) SelectInto(dest *PointJacobian, x uint8) {
	if x >= 16 {
		panic("curve256k1: out-of-bounds: " + strconv.Itoa(int(x)))
	}
	dest.Zero()
	for i := uint8(1); i < 16; i++ {
		cond := subtle.ConstantTimeByteEq(x, i)
		dest.Select(&v.points[i-1], dest, cond)
	}
}
