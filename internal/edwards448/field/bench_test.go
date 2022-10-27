package field

import "testing"

func BenchmarkAdd(b *testing.B) {
	var x, y Element
	x.One()
	y.Add(feOne, feOne)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Add(&x, &y)
	}
}

func BenchmarkMul(b *testing.B) {
	var x, y Element
	x.One()
	y.Add(feOne, feOne)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul(&x, &y)
	}
}

func BenchmarkSquare(b *testing.B) {
	var x Element
	x.One()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Square(&x)
	}
}

func BenchmarkInv(b *testing.B) {
	var x Element
	x.One()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Inv(&x)
	}
}

func BenchmarkSqrtRatio(b *testing.B) {
	var u Element
	var v Element
	u.One()
	v.One()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u.SqrtRatio(&u, &v)
	}
}
