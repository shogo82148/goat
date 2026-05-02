package field

import "testing"

func BenchmarkAdd(b *testing.B) {
	var x, y Element
	x.One()
	y.Add(feOne, feOne)
	for b.Loop() {
		x.Add(&x, &y)
	}
}

func BenchmarkSub(b *testing.B) {
	var x, y Element
	x.One()
	y.Add(feOne, feOne)
	for b.Loop() {
		x.Sub(&x, &y)
	}
}

func BenchmarkNegate(b *testing.B) {
	var x Element
	x.One()
	for b.Loop() {
		x.Negate(&x)
	}
}

func BenchmarkSetBytes(b *testing.B) {
	var x Element
	data := []byte{
		0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	for b.Loop() {
		x.SetBytes(data)
	}
}

func BenchmarkEqual1(b *testing.B) {
	x := &Element{1, 1, 1, 1, 1, 1, 1, 1}
	y := &Element{8, 7, 6, 5, 4, 3, 2, 1}
	for b.Loop() {
		x.Equal(y)
	}
}

func BenchmarkEqual2(b *testing.B) {
	x := &Element{1, 1, 1, 1, 1, 1, 1, 1}
	y := &Element{1, 1, 1, 1, 1, 1, 1, 1}
	for b.Loop() {
		x.Equal(y)
	}
}

func BenchmarkMul32(b *testing.B) {
	var x Element
	x.One()
	for b.Loop() {
		x.Mul32(&x, 2)
	}
}

func BenchmarkMul(b *testing.B) {
	var x, y Element
	x.One()
	y.Add(feOne, feOne)
	for b.Loop() {
		x.Mul(&x, &y)
	}
}

func BenchmarkSquare(b *testing.B) {
	var x Element
	x.One()
	for b.Loop() {
		x.Square(&x)
	}
}

func BenchmarkInv(b *testing.B) {
	var x Element
	x.One()
	for b.Loop() {
		x.Inv(&x)
	}
}

func BenchmarkSqrtRatio(b *testing.B) {
	var u Element
	var v Element
	u.One()
	v.One()
	for b.Loop() {
		u.SqrtRatio(&u, &v)
	}
}
