package jws

import (
	"bytes"
	"context"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/hs" // for HMAC SHA-256
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

func TestParse(t *testing.T) {
	t.Run("RFC7515 Appendix A.1 Example JWS Using HMAC SHA-256", func(t *testing.T) {
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
		msg, err := Parse(context.TODO(), raw, FindKeyFunc(func(ctx context.Context, header *Header) (sig.Key, error) {
			alg := header.Algorithm.New()
			return alg.NewKey(key.PrivateKey, key.PublicKey), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if want, got := msg.Header.Algorithm, jwa.HS256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}
		if want, got := "JWT", msg.Header.Type; want != got {
			t.Errorf("unexpected type: want %s, got %s", want, got)
		}

		payload := []byte(`{"iss":"joe",` +
			`"exp":1300819380,` +
			`"http://example.com/is_root":true}`)
		if bytes.Equal(payload, msg.Payload) {
			t.Error("unexpected payload")
		}
	})
}
