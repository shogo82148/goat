package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_ecdsa(t *testing.T) {
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

func BenchmarkParseKey_ecdsa(b *testing.B) {
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

func TestParseKey_ecdsa_invalid(t *testing.T) {
	keys := []struct {
		name string
		data string
	}{
		{
			name: "invalid base64 value x",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"!!invalid base64 value!!",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "invalid base64 value y",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"y":"!!invalid base64 value!!",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "invalid curve",
			data: `{"kty":"EC",` +
				`"crv":"INVALID CURVE",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "missing parameter x",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "missing parameter y",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "missing parameter crv",
			data: `{"kty":"EC",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "invalid base64 value d",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"d":"!!invalid base64 value!!",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "invalid public key",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"00",` +
				`"y":"00",` +
				`"use":"enc",` +
				`"kid":"1"}`,
		},
		{
			name: "invalid private key",
			data: `{"kty":"EC",` +
				`"crv":"P-256",` +
				`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
				`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
				`"d":"00",` +
				`"use":"enc",` +
				`"kid":"1"}`,
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

func TestMarshalKey_ecdsa(t *testing.T) {
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
}
