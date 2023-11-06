package x25519

import (
	"bytes"
	"testing"
)

func FuzzTestX25519(f *testing.F) {
	f.Add(
		decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
		decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
	)
	f.Add(
		decodeHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
		decodeHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
	)
	f.Add(
		decodeHex("0900000000000000000000000000000000000000000000000000000000000000"),
		decodeHex("0900000000000000000000000000000000000000000000000000000000000000"),
	)
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		ret, err1 := X25519(a, b)
		legacy, err2 := x25519Legacy(a, b)
		if (err1 != nil) != (err2 != nil) {
			t.Fatal(err1, err2)
		}
		if err1 != nil || err2 != nil {
			return
		}
		if !bytes.Equal(ret, legacy) {
			t.Error("not match")
		}
	})
}
