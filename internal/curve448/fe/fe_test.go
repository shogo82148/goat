package fe

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func (v Element) String() string {
	return hex.EncodeToString(v.Bytes())
}

// weirdLimbs can be combined to generate a range of edge-case field elements.
// 0 and -1 are intentionally more weighted, as they combine well.
var (
	weirdLimbs56 = []uint64{
		0, 0, 0, 0,
		1,
		0xaaaaaaaaaaaaaa,
		0x55555555555555,
		(1 << 56) - 1, (1 << 56) - 1,
		(1 << 56) - 1, (1 << 56) - 1,
	}
	weirdLimbs57 = []uint64{
		0, 0, 0, 0, 0, 0,
		1,
		0xaaaaaaaaaaaaaa,
		0x155555555555555,
		(1 << 56) - 1, (1 << 56) - 1,
		(1 << 56) - 1, (1 << 56) - 1,
		(1 << 56) + 1,
		1 << 56,
	}
)

func generateWeirdFieldElement(rand *mathrand.Rand) Element {
	return Element{
		weirdLimbs57[rand.Intn(len(weirdLimbs57))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
		weirdLimbs57[rand.Intn(len(weirdLimbs57))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
		weirdLimbs56[rand.Intn(len(weirdLimbs56))],
	}
}

func generateFieldElement(rand *mathrand.Rand) Element {
	const maskLow57Bits = (1 << 57) - 1
	return Element{
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
		rand.Uint64() & maskLow57Bits,
	}
}

func (Element) Generate(rand *mathrand.Rand, size int) reflect.Value {
	if rand.Intn(2) == 0 {
		return reflect.ValueOf(generateWeirdFieldElement(rand))
	}
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInBounds returns whether the element is within the expected bit size bounds
// after a light reduction.
func isInBounds(x *Element) bool {
	return bits.Len64(x.l0) <= 57 &&
		bits.Len64(x.l1) <= 57 &&
		bits.Len64(x.l2) <= 57 &&
		bits.Len64(x.l3) <= 57 &&
		bits.Len64(x.l4) <= 57 &&
		bits.Len64(x.l5) <= 57 &&
		bits.Len64(x.l6) <= 57 &&
		bits.Len64(x.l7) <= 57
}

func swapEndianness(buf []byte) []byte {
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	return buf
}

func TestBytesBigEquivalence(t *testing.T) {
	f1 := func(in [56]byte, fe, fe1 Element) bool {
		fe.SetBytes(in[:])

		b := new(big.Int).SetBytes(swapEndianness(in[:]))
		fe1.fromBig(b)

		if fe != fe1 {
			return false
		}

		buf := make([]byte, 56)
		buf = swapEndianness(fe1.toBig().FillBytes(buf))

		return bytes.Equal(fe.Bytes(), buf) && isInBounds(&fe) && isInBounds(&fe1)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Error(err)
	}
}

// fromBig sets v = n, and returns v. The bit length of n must not exceed 256.
func (v *Element) fromBig(n *big.Int) *Element {
	if n.BitLen() > 56*8 {
		panic("invalid field element input size")
	}

	buf := make([]byte, 0, 56)
	for _, word := range n.Bits() {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) >= cap(buf) {
				break
			}
			buf = append(buf, byte(word))
			word >>= 8
		}
	}

	v.SetBytes(buf[:56])
	return v
}

// toBig returns v as a big.Int.
func (v *Element) toBig() *big.Int {
	buf := v.Bytes()

	words := make([]big.Word, 56*8/bits.UintSize)
	for n := range words {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) == 0 {
				break
			}
			words[n] |= big.Word(buf[0]) << big.Word(i)
			buf = buf[1:]
		}
	}

	return new(big.Int).SetBits(words)
}

func TestAdd(t *testing.T) {
	tests := []struct {
		x, y Element
		r    Element
	}{
		{
			x: Element{0, 0, 0, 0, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 0},
			r: Element{0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, test := range tests {
		var r Element
		r.Add(&test.x, &test.y)
		r.reduce()
		if r != test.r {
			t.Errorf("got %#v, want %#v", r, test.r)
		}
	}
}

func TestAdd_Check(t *testing.T) {
	p := newP()
	f := func(a, b Element) bool {
		var v Element
		v.Add(&a, &b)

		aa := a.toBig()
		bb := b.toBig()
		vv := new(big.Int).Add(aa, bb)
		vv = vv.Mod(vv, p)

		return v.toBig().Cmp(vv) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestSub(t *testing.T) {
	tests := []struct {
		x, y Element
		r    Element
	}{
		{
			x: Element{0, 0, 0, 0, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 0},
			r: Element{0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, test := range tests {
		var r Element
		r.Sub(&test.x, &test.y)
		r.reduce()
		if r != test.r {
			t.Errorf("got %#v, want %#v", r, test.r)
		}
	}
}

func TestSub_Check(t *testing.T) {
	p := newP()
	f := func(a, b Element) bool {
		var v Element
		v.Sub(&a, &b)

		aa := a.toBig()
		bb := b.toBig()
		vv := new(big.Int).Set(p) // To avoid overflow
		vv = vv.Add(vv, aa)
		vv = vv.Sub(vv, bb)
		vv = vv.Mod(vv, p)

		return v.toBig().Cmp(vv) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestEqual(t *testing.T) {
	x := Element{1, 1, 1, 1, 1, 1, 1, 1}
	y := Element{8, 7, 6, 5, 4, 3, 2, 1}

	eq := x.Equal(&x)
	if eq != 1 {
		t.Errorf("wrong about equality")
	}

	eq = x.Equal(&y)
	if eq != 0 {
		t.Errorf("wrong about inequality")
	}
}

func TestMul(t *testing.T) {
	tests := []struct {
		x, y Element
		r    Element
	}{
		{
			x: Element{1, 0, 0, 0, 0, 0, 0, 0},
			y: Element{1, 0, 0, 0, 0, 0, 0, 0},
			r: Element{1, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			x: Element{0, 1, 0, 0, 0, 0, 0, 0},
			y: Element{0, 1, 0, 0, 0, 0, 0, 0},
			r: Element{0, 0, 1, 0, 0, 0, 0, 0},
		},
		{
			x: Element{0, 1, 0, 0, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 1, 0},
			r: Element{0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			x: Element{0, 1, 0, 0, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{1, 0, 0, 0, 1, 0, 0, 0},
		},
		{
			x: Element{0, 0, 0, 0, 1, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{0, 0, 0, 1, 0, 0, 0, 1},
		},
		{
			x: Element{0, 0, 0, 0, 0, 1, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{1, 0, 0, 0, 2, 0, 0, 0},
		},
		{
			x: Element{0, 0, 0, 0, 0, 0, 1, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{0, 1, 0, 0, 0, 2, 0, 0},
		},
		{
			x: Element{0, 0, 0, 0, 0, 0, 0, 1},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{0, 0, 1, 0, 0, 0, 2, 0},
		},
		{
			x: Element{
				0xaaaaaaaaaaaaaa, 0, 0, 0, 0, 0, 0, 0,
			},
			y: Element{
				0xaaaaaaaaaaaaaa, 0, 0, 0, 0, 0, 0, 0,
			},
			r: Element{
				0xe38e38e38e38e4, 0x71c71c71c71c70, 0, 0, 0, 0, 0, 0,
			},
		},
		{
			x: Element{1, 0, 0, 0, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 1, 0, 0, 0},
			r: Element{0, 0, 0, 0, 1, 0, 0, 0},
		},
		{
			x: Element{0, 1, 1, 1, 0, 0, 0, 1},
			y: Element{0, 1, 0, 0, 1, 0, 0, 1},
			r: Element{2, 1, 3, 2, 3, 2, 4, 2},
		},
		{
			x: Element{0, 0, 0, 1, 0, 0, 0, 0},
			y: Element{0, 0, 0, 1, 0, 0, 1, 0},
			r: Element{0, 1, 0, 0, 0, 1, 1, 0},
		},
		{
			x: Element{0, 0, 0, 0, 1, 0, 0, 1},
			y: Element{0, 1, 0, 1, 0, 0, 0, 1},
			r: Element{1, 0, 2, 1, 1, 1, 3, 2},
		},
		{
			x: Element{1, 0, 0, 1, 0, 0, 0, 0},
			y: Element{0, 0, 0, 0, 0, 0, 0, 1},
			r: Element{0, 0, 1, 0, 0, 0, 1, 1},
		},
		{
			x: Element{0, 0, 0, 0, 1, 0, 1, 1},
			y: Element{0, 1, 1, 1, 0, 1, 0, 0},
			r: Element{3, 3, 1, 1, 4, 4, 2, 3},
		},
	}
	for _, test := range tests {
		var r Element
		r.Mul(&test.x, &test.y)
		if r != test.r {
			t.Errorf("got %#v, want %#v", r, test.r)
		}
	}
}

func TestMul_Check(t *testing.T) {
	p := newP()
	f := func(a, b Element) bool {
		var v Element
		v.Mul(&a, &b)

		aa := a.toBig()
		bb := b.toBig()
		vv := new(big.Int).Mul(aa, bb)
		vv = vv.Mod(vv, p)

		return v.toBig().Cmp(vv) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func newP() *big.Int {
	var p *big.Int
	one := big.NewInt(1)
	n448 := new(big.Int).Lsh(one, 448)
	n224 := new(big.Int).Lsh(one, 224)
	p = new(big.Int).Sub(n448, n224)
	p = p.Sub(p, one)
	return p
}

func TestSelectSwap(t *testing.T) {
	a := Element{
		0xbeee3fe4f8720f, 0xaf4abe14cdfa87, 0x743db59a7609ca, 0xa305baf38087e1,
		0x636c880ad0ba04, 0x9c67547aef0e39, 0xc762e2e801e21c, 0x36fccdeaaafccc,
	}
	b := Element{
		0x4e4fd52cfb4cc0, 0x27311d6937b71d, 0x01e04a5644c6f4, 0x3e8bf7151334b9,
		0x9c4060a93baedc, 0x82486c2061b8f6, 0xed8ab5be2052d9, 0x9b9c0d091de1e8,
	}

	var c, d Element

	c.Select(&a, &b, 1)
	d.Select(&a, &b, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Select failed")
	}

	c.Swap(&d, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Swap failed")
	}

	c.Swap(&d, 1)

	if c.Equal(&b) != 1 || d.Equal(&a) != 1 {
		t.Errorf("Swap failed")
	}
}

func TestInv(t *testing.T) {
	var zero, one Element
	one.One()
	f := func(x Element) bool {
		if x == zero {
			return true
		}
		var r, inv Element
		inv.Inv(&x)
		r.Mul(&x, &inv)
		r.reduce()
		return r == one
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
