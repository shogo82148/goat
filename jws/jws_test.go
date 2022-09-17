package jws

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/shogo82148/goat/jwa/hs"
	"github.com/shogo82148/goat/sig"
)

func TestParse(t *testing.T) {
	raw := []byte(
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	)
	msg, err := Parse(context.TODO(), raw, FindKeyFunc(func(ctx context.Context, header *Header) (sig.Key, error) {
		alg := hs.NewHS256()
		k := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
		key, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			return nil, err
		}
		return alg.NewKey(key, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"iss":"joe",` +
		`"exp":1300819380,` +
		`"http://example.com/is_root":true}`)
	if bytes.Equal(payload, msg.Payload) {
		t.Error("unexpected payload")
	}
}
