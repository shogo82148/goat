package curve256k1

import (
	"bytes"
	"testing"
)

func TestScalarMult1(t *testing.T) {
	var q PointJacobian
	q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
	q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
	q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
	k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")

	q.ScalarMult(&q, k)

	wantX := decodeHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	wantY := decodeHex("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb")
	if x := q.x.Bytes(); bytes.Equal(x, wantX) {
		t.Errorf("want %x, got %x", wantX, x)
	}
	if y := q.y.Bytes(); bytes.Equal(y, wantY) {
		t.Errorf("want %x, got %x", wantY, y)
	}
}

func TestScalarMinus1(t *testing.T) {
	var q PointJacobian
	q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
	q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
	q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
	k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")

	q.ScalarMult(&q, k)

	wantX := decodeHex("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14")
	wantY := decodeHex("2c68ad3fed8a15649e39866ff96dbc3ea7c8c28ab5ab46532d17193924987c74")
	if x := q.x.Bytes(); bytes.Equal(x, wantX) {
		t.Errorf("want %x, got %x", wantX, x)
	}
	if y := q.y.Bytes(); bytes.Equal(y, wantY) {
		t.Errorf("want %x, got %x", wantY, y)
	}
}

func BenchmarkScalarMult1(b *testing.B) {
	var q PointJacobian
	q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
	q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
	q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
	k := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.ScalarMult(&q, k)
	}
}

func BenchmarkScalarMultMinus1(b *testing.B) {
	var q PointJacobian
	q.x.Set(hex2element("79b1031b16eaed727f951f0fadeebc9a950092861fe266869a2e57e6eda95a14"))
	q.y.Set(hex2element("d39752c01275ea9b61c67990069243c158373d754a54b9acd2e8e6c5db677fbb"))
	q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))
	k := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.ScalarMult(&q, k)
	}
}
