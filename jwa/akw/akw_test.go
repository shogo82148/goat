package akw

import (
	"bytes"
	"crypto/subtle"
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
	t.Run("RFC 3394 Section 4.1 Wrap 128 bits of Key Data with a 128-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F")
		cek := mustHex("00112233445566778899AABBCCDDEEFF")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
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

	t.Run("RFC 3394 Section 4.2 Wrap 128 bits of Key Data with a 192-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F1011121314151617")
		cek := mustHex("00112233445566778899AABBCCDDEEFF")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("96778B25AE6CA435" +
			"F92B5B97C050AED2" +
			"468AB8A17AD84E5D")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.3 Wrap 128 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		cek := mustHex("00112233445566778899AABBCCDDEEFF")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("64E8C3F9CE0F5BA2" +
			"63E9777905818A2A" +
			"93C8191E7D6E8AE7")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.4 Wrap 192 bits of Key Data with a 192-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F1011121314151617")
		cek := mustHex("00112233445566778899AABBCCDDEEFF0001020304050607")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("031D33264E15D332" +
			"68F24EC260743EDC" +
			"E1C6C7DDEE725A93" +
			"6BA814915C6762D2")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.5 Wrap 192 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		cek := mustHex("00112233445566778899AABBCCDDEEFF0001020304050607")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("A8F9BC1612C68B3F" +
			"F6E6F4FBE30E71E4" +
			"769C8B80A32CB895" +
			"8CD5D17D6B254DA1")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.6 Wrap 256 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		cek := mustHex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
		w := NewKeyWrapper(key)
		_, got, err := w.WrapKey(cek)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex("28C9F404C4B810F4" +
			"CBCCB35CFB87F826" +
			"3F5786E2D80ED326" +
			"CBC7F0E71A99F43B" +
			"FB988B9B7A02DD21")

		if !bytes.Equal(want, got) {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		jsonKey := `{"kty":"oct",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"` +
			`}`
		key, err := jwk.ParseKey([]byte(jsonKey))
		if err != nil {
			t.Fatal(err)
		}
		w := NewKeyWrapper(key.PrivateKey.([]byte))

		cek := []byte{
			4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
			206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
			44, 207,
		}
		_, got, err := w.WrapKey(cek)
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

func TestUnwrap(t *testing.T) {
	t.Run("RFC 3394 Section 4.1 Wrap 128 bits of Key Data with a 128-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F")
		data := mustHex("1FA68B0A8112B447" +
			"AEF34BD8FB5A7B82" +
			"9D3E862371D2CFE5")
		want := mustHex("00112233445566778899AABBCCDDEEFF")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.2 Wrap 128 bits of Key Data with a 192-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F1011121314151617")
		data := mustHex("96778B25AE6CA435" +
			"F92B5B97C050AED2" +
			"468AB8A17AD84E5D")
		want := mustHex("00112233445566778899AABBCCDDEEFF")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.3 Wrap 128 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		data := mustHex("64E8C3F9CE0F5BA2" +
			"63E9777905818A2A" +
			"93C8191E7D6E8AE7")
		want := mustHex("00112233445566778899AABBCCDDEEFF")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.4 Wrap 192 bits of Key Data with a 192-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F1011121314151617")
		data := mustHex("031D33264E15D332" +
			"68F24EC260743EDC" +
			"E1C6C7DDEE725A93" +
			"6BA814915C6762D2")
		want := mustHex("00112233445566778899AABBCCDDEEFF0001020304050607")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.5 Wrap 192 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		data := mustHex("A8F9BC1612C68B3F" +
			"F6E6F4FBE30E71E4" +
			"769C8B80A32CB895" +
			"8CD5D17D6B254DA1")
		want := mustHex("00112233445566778899AABBCCDDEEFF0001020304050607")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 3394 Section 4.6 Wrap 256 bits of Key Data with a 256-bit KEK", func(t *testing.T) {
		key := mustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		data := mustHex("28C9F404C4B810F4" +
			"CBCCB35CFB87F826" +
			"3F5786E2D80ED326" +
			"CBC7F0E71A99F43B" +
			"FB988B9B7A02DD21")
		want := mustHex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")

		w := NewKeyWrapper(key)
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})

	t.Run("RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		jsonKey := `{"kty":"oct",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"` +
			`}`
		key, err := jwk.ParseKey([]byte(jsonKey))
		if err != nil {
			t.Fatal(err)
		}
		w := NewKeyWrapper(key.PrivateKey.([]byte))

		data := []byte{
			232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
			22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
			76, 124, 193, 11, 98, 37, 173, 61, 104, 57,
		}
		want := []byte{
			4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
			206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
			44, 207,
		}
		got, err := w.UnwrapKey(nil, data)
		if err != nil {
			t.Fatal(err)
		}

		if subtle.ConstantTimeCompare(want, got) == 0 {
			t.Errorf("want %#v, got %#v", want, got)
		}
	})
}
