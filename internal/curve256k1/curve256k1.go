package curve256k1

import (
	"errors"
	"math/big"

	"github.com/shogo82148/goat/internal/curve256k1/field"
)

type Point struct {
	x, y field.Element
}

var feZero field.Element
var fe7 field.Element

func init() {
	if err := fe7.SetBytes([]byte{0x07}); err != nil {
		panic(err)
	}
}

func (p *Point) NewPoint(x, y *big.Int) (*Point, error) {
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}
	if x.BitLen() > 256 || y.BitLen() > 256 {
		return nil, errors.New("overflowing coordinate")
	}
	var buf [32]byte
	x.FillBytes(buf[:])
	if err := p.x.SetBytes(buf[:]); err != nil {
		return nil, err
	}
	y.FillBytes(buf[:])
	if err := p.y.SetBytes(buf[:]); err != nil {
		return nil, err
	}
	return p, nil
}

func IsOnCurve(p *Point) bool {
	// x^3
	var x3 field.Element
	x3.Square(&p.x)
	x3.Mul(&x3, &p.x)

	// y^2
	var y2 field.Element
	y2.Square(&p.y)

	// x^3 - y^2 + 7
	var ret field.Element
	ret.Sub(&x3, &y2)
	ret.Add(&ret, &fe7)

	return ret.Equal(&feZero) == 1
}
