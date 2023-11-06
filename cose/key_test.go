package cose

import (
	"bytes"
	"os"
	"testing"

	"github.com/shogo82148/go-cbor"
)

func TestParseMap(t *testing.T) {
	data, err := os.ReadFile("testdata/cose-wg-examples/KeySet.txt")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cbor.DecodeEDN(data)
	if err != nil {
		t.Fatal(err)
	}

	var set []map[any]any
	dec := cbor.NewDecoder(bytes.NewReader(msg))
	dec.UseAnyKey()
	dec.UseInteger()
	if err := dec.Decode(&set); err != nil {
		t.Fatal(err)
	}

	t.Run("0", func(t *testing.T) {
		key, err := ParseMap(set[0])
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != KeyTypeEC2 {
			t.Errorf("unexpected key type: %v", key.kty)
		}
		if string(key.KeyID()) != "11" {
			t.Errorf("unexpected key id: %v,  want 11", key.kid)
		}
		if key.Curve() != CurveP256 {
			t.Errorf("unexpected curve: %v", key.crv)
		}
		if got, want := key.X(), []byte{0xba, 0xc5, 0xb1, 0x1c, 0xad, 0x8f, 0x99, 0xf9, 0xc7, 0x2b, 0x05, 0xcf, 0x4b, 0x9e, 0x26, 0xd2, 0x44, 0xdc, 0x18, 0x9f, 0x74, 0x52, 0x28, 0x25, 0x5a, 0x21, 0x9a, 0x86, 0xd6, 0xa0, 0x9e, 0xff}; !bytes.Equal(got, want) {
			t.Errorf("unexpected x: %x, want %x", got, want)
		}
		if got, want := key.Y(), []byte{0x20, 0x13, 0x8b, 0xf8, 0x2d, 0xc1, 0xb6, 0xd5, 0x62, 0xbe, 0x0f, 0xa5, 0x4a, 0xb7, 0x80, 0x4a, 0x3a, 0x64, 0xb6, 0xd7, 0x2c, 0xcf, 0xed, 0x6b, 0x6f, 0xb6, 0xed, 0x28, 0xbb, 0xfc, 0x11, 0x7e}; !bytes.Equal(got, want) {
			t.Errorf("unexpected y: %x, want %x", got, want)
		}
	})
}
