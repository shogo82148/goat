package edwards448

import (
	"crypto/subtle"
	"sync"
)

type lookupTable struct {
	points [8]Point
}

var initBasepointOnce sync.Once
var varBasepointTable [56]lookupTable

// basepointTable is a set of 32 affineLookupTables, where table i is generated
// from 256i * basepoint. It is precomputed the first time it's used.
func basepointTable() *[56]lookupTable {
	initBasepointOnce.Do(func() {
		p := NewGeneratorPoint()
		for i := 0; i < 56; i++ {
			varBasepointTable[i].Init(p)
			for j := 0; j < 8; j++ {
				p.Add(p, p)
			}
		}
	})
	return &varBasepointTable
}

func (v *lookupTable) Init(p *Point) {
	// Goal: v.points[i] = (i+1)*Q, i.e., Q, 2Q, ..., 8Q
	// This allows lookup of -8Q, ..., -Q, 0, Q, ..., 8Q
	points := &v.points
	points[0].Set(p)
	for i := 1; i < 8; i++ {
		var v Point
		points[i].Set(v.Add(&points[i-1], p))
	}
}

// Set dest to x*Q, where -8 <= x <= 8, in constant time.
func (v *lookupTable) SelectInto(dest *Point, x int8) {
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
