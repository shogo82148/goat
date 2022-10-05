package jwk

import (
	"bytes"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_Symmetric(t *testing.T) {
	t.Run("RFC7515 Appendix A.1 Example JWS Using HMAC SHA-256", func(t *testing.T) {
		rawKey := `{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.kty)
		}
		got, ok := key.PrivateKey().([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey)
		}
		want := []byte{
			0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
			0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
			0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
			0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
			0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
			0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
			0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
			0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
		}
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		rawKey := `{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.kty)
		}
		if key.alg != "A128KW" {
			t.Errorf("unexpected algorithm: want %s, got %s", "A128KW", key.alg)
		}
		got, ok := key.PrivateKey().([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey)
		}
		want := []byte{
			0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5,
			0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52,
		}
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(t *testing.T) {
		rawKey := `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.Oct {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.kty)
		}
		got, ok := key.PrivateKey().([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey)
		}
		want := []byte{
			0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
			0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
			0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
			0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
			0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
			0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
			0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
			0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
		}
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})
}

func BenchmarkParseKey_Symmetric(b *testing.B) {
	b.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestParseKey_Symmetric_Invalid(t *testing.T) {
	keys := []struct {
		name string
		data string
	}{
		{
			name: "invalid base64 value k",
			data: `{"kty":"oct","alg":"A128KW","k":"!!invalid base64 value!!"}`,
		},
		{
			name: "missing required parameter k",
			data: `{"kty":"oct","alg":"A128KW"}`,
		},
	}

	for _, key := range keys {
		_, err := ParseKey([]byte(key.data))
		t.Logf("%s: %v", key.name, err)
		if err == nil {
			t.Errorf("want error, but not: %s", key.name)
		}
	}
}

func TestMarshalKey_symmetric(t *testing.T) {
	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		key := &Key{
			alg: jwa.A128KW.KeyAlgorithm(),
			priv: []byte{
				0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5,
				0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(t *testing.T) {
		key := &Key{
			kid: "HMAC key used in JWS spec Appendix A.1 example",
			priv: []byte{
				0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
				0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
				0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
				0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
				0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
				0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
				0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
				0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example","kty":"oct"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})
}
