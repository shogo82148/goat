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
		if key.kty != KeyTypeEC2 {
			t.Errorf("unexpected key type: %v", key.kty)
		}
	})
}
