package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestParseKey_ecdsa(t *testing.T) {
	t.Run("RFC 7515 Appendix A.3 Example JWS Using ECDSA P-256 SHA-256", func(t *testing.T) {
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
		if want, got := key.kty, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x := newBigInt("57807358241436249728379122087876380298924820027722995515715270765240753673285")
		y := newBigInt("90436541859143682268950424386863654389577770182238183823381687388274600502701")
		want := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		got := key.PublicKey()
		if !want.Equal(got) {
			t.Errorf("unexpected public key: want %v, got %v", want, got)
		}

		d := newBigInt("64502400493437371358766275827725703314178640739253280897215993954599262549170")
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *want,
			D:         d,
		}
		if !privateKey.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey())
		}
	})

	t.Run("RFC 7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
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
		if want, got := key.kty, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x := newBigInt("6558566456959953544109522959384633002634366184193672267866407124696200040032063394775499664830638630438428532794662648623689740875293641365317574204038644132")
		y := newBigInt("705914061082973601048865942513844186912223650952616397119610620188911564288314145208762412315826061109317770515164005156360031161563418113875601542699600118")
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     x,
			Y:     y,
		}
		if !publicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected public key: want %v, got %v", publicKey, key.PublicKey())
		}

		d := newBigInt("5341829702302574813496892344628933729576493483297373613204193688404465422472930583369539336694834830511678939023627363969939187661870508700291259319376559490")
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *publicKey,
			D:         d,
		}
		if !privateKey.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey())
		}
	})

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
		if want, got := key.kty, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x := newBigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238")
		y := newBigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915")
		want := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		got := key.PublicKey()
		if !want.Equal(got) {
			t.Errorf("unexpected public key: want %v, got %v", want, got)
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
		if want, got := key.kty, jwa.EC; want != got {
			t.Errorf("unexpected key type: want %s, got %s", want, got)
		}
		x := newBigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238")
		y := newBigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915")
		want := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		got := key.PublicKey()
		if !want.Equal(got) {
			t.Errorf("unexpected public key: want %v, got %v", want, got)
		}

		d := newBigInt("110246039328358150430804407946042381407500908316371398015658902487828646033409")
		privateKey := &ecdsa.PrivateKey{
			PublicKey: *want,
			D:         d,
		}
		if !privateKey.Equal(key.PrivateKey()) {
			t.Errorf("unexpected private key: want %v, got %v", privateKey, key.PrivateKey())
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
		x := newBigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238")
		y := newBigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915")
		key := &Key{
			kty: jwa.EC,
			kid: "1",
			use: "enc",
			pub: &ecdsa.PublicKey{
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
		x := newBigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238")
		y := newBigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915")
		d := newBigInt("110246039328358150430804407946042381407500908316371398015658902487828646033409")
		key := &Key{
			priv: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				},
				D: d,
			},
			pub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
			use: "enc",
			kid: "1",
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

	t.Run("RFC 7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
		x := newBigInt("6558566456959953544109522959384633002634366184193672267866407124696200040032063394775499664830638630438428532794662648623689740875293641365317574204038644132")
		y := newBigInt("705914061082973601048865942513844186912223650952616397119610620188911564288314145208762412315826061109317770515164005156360031161563418113875601542699600118")
		d := newBigInt("5341829702302574813496892344628933729576493483297373613204193688404465422472930583369539336694834830511678939023627363969939187661870508700291259319376559490")
		key := &Key{
			priv: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     x,
					Y:     y,
				},
				D: d,
			},
			pub: &ecdsa.PublicKey{
				Curve: elliptic.P521(),
				X:     x,
				Y:     y,
			},
		}
		got, err := key.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
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
}
