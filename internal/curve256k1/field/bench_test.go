package field

import "testing"

func BenchmarkAdd(b *testing.B) {
	var x, y Element
	y.One()
	for b.Loop() {
		x.Add(&x, &y)
	}
}

func BenchmarkSub(b *testing.B) {
	var x, y Element
	y.One()

	for b.Loop() {
		x.Sub(&x, &y)
	}
}

func BenchmarkNeg(b *testing.B) {
	var x Element
	x.One()

	for b.Loop() {
		x.Neg(&x)
	}
}

func BenchmarkMul(b *testing.B) {
	var x, y Element
	y.One()
	x.One()
	x.Add(&x, &x)

	for b.Loop() {
		x.Mul(&x, &y)
	}
}

func BenchmarkSquare(b *testing.B) {
	var x Element
	x.One()
	x.Add(&x, &x)

	for b.Loop() {
		x.Square(&x)
	}
}

func BenchmarkInv(b *testing.B) {
	var x Element
	x.One()
	x.Add(&x, &x)

	for b.Loop() {
		x.Inv(&x)
	}
}
