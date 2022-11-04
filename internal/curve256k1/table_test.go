package curve256k1

import "testing"

func TestTable(t *testing.T) {
	var q PointJacobian
	q.x.Set(hex2element("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
	q.y.Set(hex2element("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))
	q.z.Set(hex2element("0000000000000000000000000000000000000000000000000000000000000001"))

	var table lookupTable
	table.Init(&q)

	var r PointJacobian
	r.Zero()
	for i := 0; i < 16; i++ {
		var got PointJacobian
		table.SelectInto(&got, uint8(i))
		if r.Equal(&got) == 0 {
			t.Errorf("table[%d].x: want %x, got %x", i, r.x.Bytes(), got.x.Bytes())
			t.Errorf("table[%d].y: want %x, got %x", i, r.y.Bytes(), got.y.Bytes())
			t.Errorf("table[%d].z: want %x, got %x", i, r.z.Bytes(), got.z.Bytes())
		}
		r.Add(&r, &q)
	}
}
