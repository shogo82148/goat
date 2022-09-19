package jwt

import (
	"context"
	"testing"
	"time"

	_ "github.com/shogo82148/goat/jwa/hs"   // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/none" // for none
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

func TestParse(t *testing.T) {
	nowFunc = func() time.Time {
		return time.Unix(1300819379, 0)
	}
	defer func() {
		nowFunc = time.Now
	}()

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
		token, err := Parse(context.TODO(), raw, jws.FindKeyFunc(func(ctx context.Context, header *jws.Header) (sig.Key, error) {
			alg := header.Algorithm.New()
			return alg.NewKey(key.PrivateKey, key.PublicKey), nil
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
		token, err := Parse(context.TODO(), raw, jws.FindKeyFunc(func(ctx context.Context, header *jws.Header) (sig.Key, error) {
			alg := header.Algorithm.New()
			return alg.NewKey(nil, nil), nil
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
