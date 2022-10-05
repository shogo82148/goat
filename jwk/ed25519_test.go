package jwk

import (
	"crypto/ed25519"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_Ed25519(t *testing.T) {
	t.Run("RFC 8037 Appendix A.1. Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.kty)
		}

		privateKey := ed25519.PrivateKey{
			0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
			0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !privateKey.Equal(key.PrivateKey) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey)
		}

		publicKey := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %x, got %x", publicKey, key.PublicKey)
		}
	})

	t.Run("RFC 8037 Appendix A.2. Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.kty)
		}

		publicKey := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %x, got %x", publicKey, key.PublicKey)
		}
	})
}

func BenchmarkParseKey_Ed25519(b *testing.B) {
	b.Run("RFC 8037 Appendix A.1. Ed25519 Private Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 8037 Appendix A.2. Ed25519 Public Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestMarshalKey_Ed25519(t *testing.T) {
	t.Run("RFC 8037 Appendix A.1. Ed25519 Private Key", func(t *testing.T) {
		key := &Key{
			PrivateKey: ed25519.PrivateKey{
				0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
				0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
			PublicKey: ed25519.PublicKey{
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"kty":"OKP",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("RFC 8037 Appendix A.2. Ed25519 Public Key", func(t *testing.T) {
		key := &Key{
			PublicKey: ed25519.PublicKey{
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"Ed25519",` +
			`"kty":"OKP",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})
}

func TestParseKey_Ed25519_Invalid(t *testing.T) {
	keys := []struct {
		name string
		data string
	}{
		{
			name: "invalid base64 value: d",
			data: `{"kty":"OKP","crv":"Ed25519",` +
				`"d":"!!invalid base64!!",` +
				`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		},
		{
			name: "invalid base64 value: x",
			data: `{"kty":"OKP","crv":"Ed25519",` +
				`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
				`"x":"!!invalid base64!!"}`,
		},
		{
			name: "missing parameter: x",
			data: `{"kty":"OKP","crv":"Ed25519",` +
				`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}`,
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
