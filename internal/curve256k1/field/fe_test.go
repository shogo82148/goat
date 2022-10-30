package field

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
	"testing/quick"
)

func decodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func (v *Element) String() string {
	return hex.EncodeToString(v.Bytes())
}

func TestBytes(t *testing.T) {
	t.Run("1", func(t *testing.T) {
		x := decodeHex("01")
		var v Element
		if err := v.SetBytes(x); err != nil {
			t.Fatal(err)
		}
		want := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")
		got := v.Bytes()
		if !bytes.Equal(got, want) {
			t.Errorf("want %x, got %x", want, got)
		}
	})
	t.Run("p-1", func(t *testing.T) {
		x := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E")
		var v Element
		if err := v.SetBytes(x); err != nil {
			t.Fatal(err)
		}
		got := v.Bytes()
		if !bytes.Equal(got, x) {
			t.Errorf("want %x, got %x", x, got)
		}
	})

	t.Run("p", func(t *testing.T) {
		x := decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
		var v Element
		if err := v.SetBytes(x); err == nil {
			t.Error("want error, but not")
		}
	})
}

func TestBytes_Quick(t *testing.T) {
	f := func(x [32]byte) bool {
		var v Element
		if err := v.SetBytes(x[:]); err != nil {
			return true
		}
		got := v.Bytes()
		return bytes.Equal(got, x[:])
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		x, y, z string
	}{
		// test of carry
		{
			x: "ffffffffffffffff",
			y: "01",
			z: "010000000000000000",
		},
		{
			x: "ffffffffffffffff0000000000000000",
			y: "010000000000000000",
			z: "0100000000000000000000000000000000",
		},
		{
			x: "ffffffffffffffff00000000000000000000000000000000",
			y: "0100000000000000000000000000000000",
			z: "01000000000000000000000000000000000000000000000000",
		},
		{
			x: "ffffffffffffffff000000000000000000000000000000000000000000000000",
			y: "01000000000000000000000000000000000000000000000000",
			z: "01000003d1",
		},

		// (-1) + 1 = 0
		{
			x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			y: "0000000000000000000000000000000000000000000000000000000000000001",
			z: "0000000000000000000000000000000000000000000000000000000000000000",
		},

		// (-1) + (-1) = -2
		{
			x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			y: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			z: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D",
		},
	}

	for _, tc := range tests {
		x := new(Element)
		y := new(Element)
		z := new(Element)
		x.SetBytes(decodeHex(tc.x))
		y.SetBytes(decodeHex(tc.y))
		z.SetBytes(decodeHex(tc.z))
		v := new(Element).Add(x, y)
		if v.Equal(z) == 0 {
			t.Errorf("%s + %s = %s, but got %s", x, y, z, v)
		}
	}
}

func TestSub(t *testing.T) {
	tests := []struct {
		x, y, z string
	}{
		// test of carry
		{
			x: "010000000000000000",
			y: "01",
			z: "ffffffffffffffff",
		},
		{
			x: "0100000000000000000000000000000000",
			y: "010000000000000000",
			z: "ffffffffffffffff0000000000000000",
		},
		{
			x: "01000000000000000000000000000000000000000000000000",
			y: "0100000000000000000000000000000000",
			z: "ffffffffffffffff00000000000000000000000000000000",
		},
		{
			x: "01000003d1",
			y: "01000000000000000000000000000000000000000000000000",
			z: "ffffffffffffffff000000000000000000000000000000000000000000000000",
		},

		// 0 - 1 = -1
		{
			x: "0000000000000000000000000000000000000000000000000000000000000000",
			y: "0000000000000000000000000000000000000000000000000000000000000001",
			z: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
		},

		{
			x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D",
			y: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			z: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
		},
	}

	for _, tc := range tests {
		x := new(Element)
		y := new(Element)
		z := new(Element)
		x.SetBytes(decodeHex(tc.x))
		y.SetBytes(decodeHex(tc.y))
		z.SetBytes(decodeHex(tc.z))
		v := new(Element).Sub(x, y)
		if v.Equal(z) == 0 {
			t.Errorf("%s - %s = %s, but got %s", x, y, z, v)
		}
	}
}

func TestMul(t *testing.T) {
	tests := []struct {
		x, y, z string
	}{
		{
			x: "0000000000000000000000000000000000000000000000000000000000000001",
			y: "0000000000000000000000000000000000000000000000000000000000000001",
			z: "0000000000000000000000000000000000000000000000000000000000000001",
		},

		// (-1) * (-1) = 1
		{
			x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			y: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
			z: "0000000000000000000000000000000000000000000000000000000000000001",
		},

		{
			x: "a6abc0eebb2fdc881683b1bed2697711907ad3129224cb32c4b4f7f92107674a",
			y: "0e1c924e10015e2f3f7a08e7be463d3a10898d7519c658d3c94b43de924cf26c",
			z: "00eb49ea0e164fc9566992701bee2ca196b8724ab01d5270e57e6094e73acd3f",
		},

		{
			x: "527e29d229aef83718f1462b4ed21fcded1678b641720386dc24c8e2b9512429",
			y: "2e13e4d2bcc909a00a761eacbe3c2b6ff0384aa12cec1edf4b944e0d51e7036a",
			z: "00f098008bb2ec1d27f884647e5799ebfeaad06938ea0ec8ee0c6a4a31a9ff25",
		},
	}

	for _, tc := range tests {
		x := new(Element)
		y := new(Element)
		z := new(Element)
		x.SetBytes(decodeHex(tc.x))
		y.SetBytes(decodeHex(tc.y))
		z.SetBytes(decodeHex(tc.z))
		v := new(Element).Mul(x, y)
		if v.Equal(z) == 0 {
			t.Errorf("%s * %s = %s, but got %s", x, y, z, v)
		}
	}
}

func TestMul_Quick(t *testing.T) {
	l, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	f := func(x, y [32]byte) bool {
		var a, b, c Element
		if err := a.SetBytes(x[:]); err != nil {
			return true
		}
		if err := b.SetBytes(y[:]); err != nil {
			return true
		}
		c.Mul(&a, &b)

		A := new(big.Int).SetBytes(x[:])
		B := new(big.Int).SetBytes(y[:])
		C := new(big.Int).Mul(A, B)
		C.Mod(C, l)

		return bytes.Equal(c.Bytes(), C.Bytes())
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestInv(t *testing.T) {
	var v, z, one Element
	one.One()
	z.One()
	z.Add(&z, &z)

	v.Inv(&z)
	v.Mul(&v, &z)
	if v.Equal(&one) != 1 {
		t.Error("incorrect")
	}
}

func TestInv_Check(t *testing.T) {
	var one Element
	one.One()
	f := func(x [32]byte) bool {
		var a Element
		if err := a.SetBytes(x[:]); err != nil {
			return true
		}
		var v Element
		v.Inv(&a)
		v.Mul(&v, &a)
		return v.Equal(&one) == 1
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
