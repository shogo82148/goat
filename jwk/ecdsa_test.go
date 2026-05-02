package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/secp256k1"
)

func TestParseKey_ecdsa(t *testing.T) {
	t.Run("RFC 7515 Appendix A.3 Example JWS Using ECDSA P-256 SHA-256", func(t *testing.T) {
		// parse JWK
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
			`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
			`}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}

		// expected private key
		data, err := hex.DecodeString("8e9b109e719098bf980487df1f5d77e9cb29606ebed2263b5f57c213df84f4b2")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
		if err != nil {
			t.Fatal(err)
		}

		// verify
		if want, got := key.kty, jwa.KeyTypeEC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected public key: want %v, got %v", priv.PublicKey, key.PublicKey())
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", priv, key.PrivateKey())
		}
	})

	t.Run("RFC 7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
		// parse JWK
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_` +
			`NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",` +
			`"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl` +
			`y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",` +
			`"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA` +
			`xerEzgdRhajnu0ferB0d53vM9mE15j2C"` +
			`}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}

		// expected private key
		data, err := hex.DecodeString("018e696fb034505881dd110b483eb87d32ce495fe36b3745edf2d8cae4f0f2539f4615a0e98eab52b3c0c5eac4ce075185a8e7bb47deac1d1de77bccf66135e63d82")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P521(), data)
		if err != nil {
			t.Fatal(err)
		}

		// verify
		if want, got := key.kty, jwa.KeyTypeEC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected public key: want %v, got %v", priv.PublicKey, key.PublicKey())
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", priv, key.PrivateKey())
		}
	})

	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		// parse JWK
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

		// expected public key
		buf, err := hex.DecodeString("0430a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3ee04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), buf)
		if err != nil {
			t.Fatal(err)
		}

		// verify
		if want, got := key.kty, jwa.KeyTypeEC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		got := key.PublicKey()
		if !pub.Equal(got) {
			t.Errorf("unexpected public key: want %v, got %v", pub, got)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		// parse JWK
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

		// expected private key
		data, err := hex.DecodeString("f3bd0c07a81fb932781ed52752f60cc89a6be5e51934fe01938ddb55d8f77801")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
		if err != nil {
			t.Fatal(err)
		}

		// verify
		if want, got := key.kty, jwa.KeyTypeEC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected public key: want %v, got %v", priv.PublicKey, key.PublicKey())
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", priv, key.PrivateKey())
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
		for b.Loop() {
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
		for b.Loop() {
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
		buf, err := hex.DecodeString("0430a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3ee04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), buf)
		if err != nil {
			t.Fatal(err)
		}

		// encode JWK
		key := &Key{
			kty: jwa.KeyTypeEC,
			kid: "1",
			use: "enc",
			pub: pub,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
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
		// expected private key
		data, err := hex.DecodeString("f3bd0c07a81fb932781ed52752f60cc89a6be5e51934fe01938ddb55d8f77801")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
		if err != nil {
			t.Fatal(err)
		}

		// encode JWK
		key := &Key{
			priv: priv,
			pub:  &priv.PublicKey,
			use:  "enc",
			kid:  "1",
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
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

	t.Run("RFC 7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
		data, err := hex.DecodeString("018e696fb034505881dd110b483eb87d32ce495fe36b3745edf2d8cae4f0f2539f4615a0e98eab52b3c0c5eac4ce075185a8e7bb47deac1d1de77bccf66135e63d82")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P521(), data)
		if err != nil {
			t.Fatal(err)
		}

		// encode JWK
		key := &Key{
			priv: priv,
			pub:  &priv.PublicKey,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
		want := `{"crv":"P-521",` +
			`"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA` +
			`xerEzgdRhajnu0ferB0d53vM9mE15j2C",` +
			`"kty":"EC",` +
			`"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_` +
			`NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",` +
			`"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl` +
			`y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"` +
			`}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %q, got %q", want, got)
		}
	})

	t.Run("secp256k1 public key using ecdsa package", func(t *testing.T) {
		x, err := hex.DecodeString("938298234af08bcf0c29767a16469aecbeba145cdd2e22323ec09ed2b98aeec2")
		if err != nil {
			t.Fatal(err)
		}
		y, err := hex.DecodeString("573ad2a075663a1c024a46e8abb1001d4af1f5eba4ed9cba574681dae450c94d")
		if err != nil {
			t.Fatal(err)
		}
		pub := &ecdsa.PublicKey{
			Curve: secp256k1.Curve(), //nolint:staticcheck // for backward compatibility
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}

		// encode JWK
		key := &Key{
			kty: jwa.KeyTypeEC,
			pub: pub,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
		want := `{"crv":"secp256k1",` +
			`"kty":"EC",` +
			`"x":"k4KYI0rwi88MKXZ6Fkaa7L66FFzdLiIyPsCe0rmK7sI",` +
			`"y":"VzrSoHVmOhwCSkboq7EAHUrx9euk7Zy6V0aB2uRQyU0"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("secp256k1 private key using ecdsa package", func(t *testing.T) {
		x, err := hex.DecodeString("938298234af08bcf0c29767a16469aecbeba145cdd2e22323ec09ed2b98aeec2")
		if err != nil {
			t.Fatal(err)
		}
		y, err := hex.DecodeString("573ad2a075663a1c024a46e8abb1001d4af1f5eba4ed9cba574681dae450c94d")
		if err != nil {
			t.Fatal(err)
		}
		d, err := hex.DecodeString("d82f6325a22b10777625a9dd7b4404a166dee9773655a4caf996b7137b86f149")
		if err != nil {
			t.Fatal(err)
		}
		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.Curve(), //nolint:staticcheck // for backward compatibility
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			D: new(big.Int).SetBytes(d),
		}

		// encode JWK
		key := &Key{
			kty:  jwa.KeyTypeEC,
			priv: priv,
			pub:  &priv.PublicKey,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
		want := `{"crv":"secp256k1",` +
			`"d":"2C9jJaIrEHd2Jande0QEoWbe6Xc2VaTK-Za3E3uG8Uk",` +
			`"kty":"EC",` +
			`"x":"k4KYI0rwi88MKXZ6Fkaa7L66FFzdLiIyPsCe0rmK7sI",` +
			`"y":"VzrSoHVmOhwCSkboq7EAHUrx9euk7Zy6V0aB2uRQyU0"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})

	t.Run("secp256k1 public key", func(t *testing.T) {
		data, err := hex.DecodeString("04938298234af08bcf0c29767a16469aecbeba145cdd2e22323ec09ed2b98aeec2573ad2a075663a1c024a46e8abb1001d4af1f5eba4ed9cba574681dae450c94d")
		if err != nil {
			t.Fatal(err)
		}
		pub, err := secp256k1.ParseUncompressedPublicKey(data)
		if err != nil {
			t.Fatal(err)
		}

		// encode JWK
		key := &Key{
			kty: jwa.KeyTypeEC,
			pub: pub,
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
		want := `{"crv":"secp256k1",` +
			`"kty":"EC",` +
			`"x":"k4KYI0rwi88MKXZ6Fkaa7L66FFzdLiIyPsCe0rmK7sI",` +
			`"y":"VzrSoHVmOhwCSkboq7EAHUrx9euk7Zy6V0aB2uRQyU0"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}

	})

	t.Run("secp256k1 private key", func(t *testing.T) {
		data, err := hex.DecodeString("d82f6325a22b10777625a9dd7b4404a166dee9773655a4caf996b7137b86f149")
		if err != nil {
			t.Fatal(err)
		}
		priv, err := secp256k1.ParseRawPrivateKey(data)
		if err != nil {
			t.Fatal(err)
		}

		// encode JWK
		key := &Key{
			priv: priv,
			pub:  priv.Public(),
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		// verify
		want := `{"crv":"secp256k1",` +
			`"d":"2C9jJaIrEHd2Jande0QEoWbe6Xc2VaTK-Za3E3uG8Uk",` +
			`"kty":"EC",` +
			`"x":"k4KYI0rwi88MKXZ6Fkaa7L66FFzdLiIyPsCe0rmK7sI",` +
			`"y":"VzrSoHVmOhwCSkboq7EAHUrx9euk7Zy6V0aB2uRQyU0"}`
		if want != string(got) {
			t.Errorf("unexpected JWK: want %s, got %s", want, got)
		}
	})
}
