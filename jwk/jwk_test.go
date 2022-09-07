package jwk

import (
	"crypto/rsa"
	"testing"
)

func TestKey_RFC7517AppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != "RSA" {
			t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType)
		}
		if key.Algorithm != "RS256" {
			t.Errorf("unexpected algorithm: want %s, got %s", "RS256", key.Algorithm)
		}
		publicKey, ok := key.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PublicKey)
		}
		if publicKey.E != 65537 {
			t.Errorf("want %d, got %d", 65537, publicKey.E)
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType != "RSA" {
			t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType)
		}
		if key.Algorithm != "RS256" {
			t.Errorf("unexpected algorithm: want %s, got %s", "RS256", key.Algorithm)
		}
		privateKey, ok := key.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PrivateKey, got %T", key.PrivateKey)
		}
		publicKey, ok := key.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PublicKey)
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			t.Error("public keys are mismatch")
		}
	})
}

func BenchmarkKey_RFC7517AppendixA(b *testing.B) {
	// b.Run("RFC 7517 A.1. Example Public Keys (EC)", func(b *testing.B) {
	// 	rawKey := []byte(`{"kty":"EC",` +
	// 		`"crv":"P-256",` +
	// 		`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
	// 		`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
	// 		`"use":"enc",` +
	// 		`"kid":"1"}`)
	// 	for i := 0; i < b.N; i++ {
	// 		ParseKey(rawKey)
	// 	}
	// })

	b.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	// b.Run("RFC 7517 A.2. Example Private Keys (EC)", func(b *testing.B) {
	// 	rawKey := []byte(`{"kty":"EC",` +
	// 		`"crv":"P-256",` +
	// 		`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
	// 		`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
	// 		`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
	// 		`"use":"enc",` +
	// 		`"kid":"1"}`)
	// 	for i := 0; i < b.N; i++ {
	// 		ParseKey(rawKey)
	// 	}
	// })

	b.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	// b.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(b *testing.B) {
	// 	rawKey := []byte(`{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`)
	// 	for i := 0; i < b.N; i++ {
	// 		ParseKey(rawKey)
	// 	}
	// })

	// b.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(b *testing.B) {
	// 	rawKey := []byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`)
	// 	for i := 0; i < b.N; i++ {
	// 		ParseKey(rawKey)
	// 	}
	// })
}
