package jwt

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/hs"   // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/none" // for none
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

func mockTime(f func() time.Time) func() {
	g := nowFunc
	nowFunc = f
	return func() {
		nowFunc = g
	}
}

func TestParse(t *testing.T) {
	defer mockTime(func() time.Time {
		return time.Unix(1300819379, 0)
	})()

	t.Run("RFC7519 Section 3.1. Example JWT", func(t *testing.T) {
		raw := []byte(
			"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		)
		rawKey := `{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		token, err := Parse(raw, FindKeyFunc(func(header *jws.Header) (sig.SigningKey, error) {
			alg := header.Algorithm().New()
			return alg.NewSigningKey(key), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		c := token.Claims
		if want, got := "joe", c.Issuer; want != got {
			t.Errorf("invalid issuer: want %q, got %q", want, got)
		}
		if want, got := time.Unix(1300819380, 0), token.Claims.ExpirationTime; !want.Equal(got) {
			t.Errorf("invalid exp claim: want %s, got %s", want, got)
		}
		if v, ok := c.Raw["http://example.com/is_root"].(bool); !ok || !v {
			t.Error("unexpected claim")
		}
	})

	t.Run("RFC7519 Section 6.1. Example Unsecured JWT", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".",
		)
		token, err := Parse(raw, FindKeyFunc(func(header *jws.Header) (sig.SigningKey, error) {
			alg := header.Algorithm().New()
			return alg.NewSigningKey(nil), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		c := token.Claims
		if want, got := "joe", c.Issuer; want != got {
			t.Errorf("invalid issuer: want %q, got %q", want, got)
		}
		if want, got := time.Unix(1300819380, 0), token.Claims.ExpirationTime; !want.Equal(got) {
			t.Errorf("invalid exp claim: want %s, got %s", want, got)
		}
		if v, ok := c.Raw["http://example.com/is_root"].(bool); !ok || !v {
			t.Error("unexpected claim")
		}
	})
}

func TestParse_Claims(t *testing.T) {
	var now time.Time
	defer mockTime(func() time.Time {
		return now
	})()

	algNone := FindKeyFunc(func(header *jws.Header) (sig.SigningKey, error) {
		alg := jwa.None.New()
		return alg.NewSigningKey(nil), nil
	})

	var err error
	var token, data []byte

	token = []byte(`{"exp":1300819380}`)
	data = []byte(
		"eyJhbGciOiJub25lIn0." + // {"alg":"none"}
			base64.RawURLEncoding.EncodeToString(token) + ".")

	now = time.Unix(1300819380, -1) // 1ns before expiration time
	_, err = Parse(data, algNone)
	if err != nil {
		t.Error(err)
	}

	now = time.Unix(1300819380, 0) // just expiration time
	_, err = Parse(data, algNone)
	if err == nil {
		t.Error("want some error, but not")
	}

	token = []byte(`{"nbf":1300819380}`)
	data = []byte(
		"eyJhbGciOiJub25lIn0." + // {"alg":"none"}
			base64.RawURLEncoding.EncodeToString(token) + ".")

	now = time.Unix(1300819380, -1) // 1ns before the token is valid
	_, err = Parse(data, algNone)
	if err == nil {
		t.Error("want some error, but not")
	}

	now = time.Unix(1300819380, 0) // just activated
	_, err = Parse(data, algNone)
	if err != nil {
		t.Error(err)
	}
}

func TestSign(t *testing.T) {

	t.Run("RFC7519 Section 3.1. Example JWT", func(t *testing.T) {
		rawKey := `{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		sigKey := jwa.HS256.New().NewSigningKey(key)

		header := new(jws.Header)
		header.SetAlgorithm(jwa.HS256)
		header.SetType("JWT")
		claims := &Claims{
			Issuer:         "joe",
			ExpirationTime: time.Unix(1300819380, 0),
			Raw: map[string]any{
				"http://example.com/is_root": true,
			},
		}

		got, err := Sign(header, claims, sigKey)
		if err != nil {
			t.Fatal(err)
		}

		want := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
			"." +
			"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0" +
			"cnVlLCJpc3MiOiJqb2UifQ" +
			"." +
			"tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34"

		if string(got) != want {
			t.Errorf("unexpected payload: want %s, got %s", want, got)
		}
	})

	t.Run("RFC7519 Section 6.1. Example Unsecured JWT", func(t *testing.T) {
		sigKey := jwa.None.New().NewSigningKey(nil)
		header := new(jws.Header)
		header.SetAlgorithm(jwa.None)
		header.SetType("JWT")
		claims := &Claims{
			Issuer:         "joe",
			ExpirationTime: time.Unix(1300819380, 0),
			Raw: map[string]any{
				"http://example.com/is_root": true,
			},
		}

		got, err := Sign(header, claims, sigKey)
		if err != nil {
			t.Fatal(err)
		}

		want := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
			"." +
			"eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0" +
			"cnVlLCJpc3MiOiJqb2UifQ" +
			"."

		if string(got) != want {
			t.Errorf("unexpected payload: want %s, got %s", want, got)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	defer mockTime(func() time.Time {
		return time.Unix(1300819379, 0)
	})()

	raw := []byte(
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	)
	rawKey := `{"kty":"oct",` +
		`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
		`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
		`}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse(raw, FindKeyFunc(func(header *jws.Header) (sig.SigningKey, error) {
			alg := header.Algorithm().New()
			return alg.NewSigningKey(key), nil
		}))
		if err != nil {
			b.Fatal(err)
		}
	}
}
