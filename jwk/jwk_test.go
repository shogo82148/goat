package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_RFC7517AppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := key.KeyType, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if want, got := key.KeyType, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		if !publicKey.Equal(key.PublicKey) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey)
		}

		d, _ := new(big.Int).SetString("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10)
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         d,
		}
		if !privateKey.Equal(key.PrivateKey) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey)
		}
	})

}

func BenchmarkParseKey_RFC7517AppendixA(b *testing.B) {
	b.Run("RFC 7517 A.1. Example Public Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RFC 7517 A.2. Example Private Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestParseKey_RFC8037AppendixA(t *testing.T) {
	t.Run("A.1. Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType)
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

	t.Run("A.2. Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != jwa.OKP {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType)
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

func BenchmarkParseKey_RFC8037AppendixA(b *testing.B) {
	b.Run("A.1. Ed25519 Private Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("A.2. Ed25519 Public Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			if _, err := ParseKey(rawKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestKey_Base64Error(t *testing.T) {
	t.Run("EC Public Keys", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"!!!INVALID BASE64!!!",` +
			`"y":"!!!INVALID BASE64!!!",` +
			`"use":"enc",` +
			`"kid":"1"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("EC Private Keys", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"!!!INVALID BASE64!!!",` +
			`"y":"!!!INVALID BASE64!!!",` +
			`"d":"!!!INVALID BASE64!!!",` +
			`"use":"enc",` +
			`"kid":"1"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"!!!INVALID BASE64!!!"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})

	t.Run("Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"!!!INVALID BASE64!!!",` +
			`"x":"!!!INVALID BASE64!!!"}`
		_, err := ParseKey([]byte(rawKey))
		if err == nil {
			t.Error("want not nil, got nil")
		}
	})
}

func TestMarshalKey_RFC7517AppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		key := &Key{
			KeyType:      jwa.EC,
			KeyID:        "1",
			PublicKeyUse: "enc",
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"P-256",` +
			`"kid":"1",` +
			`"kty":"EC",` +
			`"use":"enc",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"` +
			`}`
		if string(got) != want {
			t.Errorf("want %q, got %q", want, got)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		x, _ := new(big.Int).SetString("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10)
		y, _ := new(big.Int).SetString("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10)
		d, _ := new(big.Int).SetString("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10)
		key := &Key{
			PrivateKey: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				},
				D: d,
			},
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
			PublicKeyUse: "enc",
			KeyID:        "1",
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{"crv":"P-256",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"kid":"1",` +
			`"kty":"EC",` +
			`"use":"enc",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"` +
			`}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %q, got %q", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		key := &Key{
			Algorithm: jwa.A128KW.KeyAlgorithm(),
			PrivateKey: []byte{
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
			KeyID: "HMAC key used in JWS spec Appendix A.1 example",
			PrivateKey: []byte{
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

func TestMarshalKey_RFC8037AppendixA(t *testing.T) {
	t.Run("A.1. Ed25519 Private Key", func(t *testing.T) {
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

	t.Run("A.2. Ed25519 Public Key", func(t *testing.T) {
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
