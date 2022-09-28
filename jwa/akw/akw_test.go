package akw

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/shogo82148/goat/jwk"
)

func mustHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestWrap(t *testing.T) {
	t.Run("", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F")
		cek := mustHex("00112233445566778899AABBCCDDEEFF")
		w := New128().NewKeyWrapper(key)
		got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("1FA68B0A8112B447" +
			"AEF34BD8FB5A7B82" +
			"9D3E862371D2CFE5")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})
	t.Run("", func(t *testing.T) {
		jsonKey := `{"kty":"oct",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"` +
			`}`
		key, err := jwk.ParseKey([]byte(jsonKey))
		if err != nil {
			t.Fatal(err)
		}
		w := New128().NewKeyWrapper(key.PrivateKey)

		cek := []byte{
			4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
			206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
			44, 207,
		}
		got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{
			232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
			22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
			76, 124, 193, 11, 98, 37, 173, 61, 104, 57,
		}

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})
}
