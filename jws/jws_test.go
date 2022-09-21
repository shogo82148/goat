package jws

import (
	"bytes"
	"context"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/es"   // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"   // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/none" // for none
	_ "github.com/shogo82148/goat/jwa/rs"   // for RSASSA-PKCS1-v1_5 SHA-256
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

		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, msg.Payload) {
			t.Errorf("unexpected payload: want %q, got %q", string(payload), string(msg.Payload))
		}
	})

	t.Run("RFC7515 Appendix A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJSUzI1NiJ9" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
				"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
				"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
				"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
				"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
				"p0igcN_IoypGlUPQGe77Rw",
		)
		rawKey := `{"kty":"RSA",` +
			`"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx` +
			`HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs` +
			`D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH` +
			`SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV` +
			`MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8` +
			`NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",` +
			`"e":"AQAB",` +
			`"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I` +
			`jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0` +
			`BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn` +
			`439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT` +
			`CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh` +
			`BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",` +
			`"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi` +
			`YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG` +
			`BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",` +
			`"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa` +
			`ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA` +
			`-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",` +
			`"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q` +
			`CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb` +
			`34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",` +
			`"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa` +
			`7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky` +
			`NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",` +
			`"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o` +
			`y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU` +
			`W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"` +
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

		if want, got := msg.Header.Algorithm, jwa.RS256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, msg.Payload) {
			t.Errorf("unexpected payload: want %q, got %q", string(payload), string(msg.Payload))
		}
	})

	t.Run("RFC7515 Appendix A.3 Example JWS Using ECDSA P-256 SHA-256", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJFUzI1NiJ9" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
				"pmWQxfKTUJqPP3-Kg6NU1Q",
		)
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
			`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
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

		if want, got := msg.Header.Algorithm, jwa.ES256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, msg.Payload) {
			t.Errorf("unexpected payload: want %q, got %q", string(payload), string(msg.Payload))
		}
	})

	t.Run("RFC7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJFUzUxMiJ9" +
				"." +
				"UGF5bG9hZA" +
				"." +
				"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq" +
				"wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp" +
				"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",
		)
		rawKey := `{"kty":"EC",` +
			`"crv":"P-521",` +
			`"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_` +
			`NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",` +
			`"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl` +
			`y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",` +
			`"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA` +
			`xerEzgdRhajnu0ferB0d53vM9mE15j2C"` +
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

		if want, got := msg.Header.Algorithm, jwa.ES512; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		payload := []byte(`Payload`)
		if !bytes.Equal(payload, msg.Payload) {
			t.Errorf("unexpected payload: want %q, got %q", string(payload), string(msg.Payload))
		}
	})

	t.Run("RFC7515 Appendix A.5 Example Unsecured JWS", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".",
		)
		msg, err := Parse(context.TODO(), raw, FindKeyFunc(func(ctx context.Context, header *Header) (sig.Key, error) {
			alg := header.Algorithm.New()
			return alg.NewKey(nil, nil), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if want, got := msg.Header.Algorithm, jwa.None; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, msg.Payload) {
			t.Errorf("unexpected payload: want %q, got %q", string(payload), string(msg.Payload))
		}
	})
}

func TestSign(t *testing.T) {
	t.Run("RFC7515 Appendix A.1 Example JWS Using HMAC SHA-256", func(t *testing.T) {
		rawKey := `{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		k := jwa.HS256.New().NewKey(key.PrivateKey, key.PrivateKey)
		h := &Header{Algorithm: jwa.HS256, Type: "JWT"}
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		got, err := Sign(h, payload, k)
		if err != nil {
			t.Fatal(err)
		}

		// It is not same with Appendix A.1 because JOSE header is compact encoded here.
		want := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"SfgggA-oZk7ztlq1i8Uz5VhmPmustakoDa9wAf8uHyQ"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	t.Run("RFC7515 Appendix A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx` +
			`HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs` +
			`D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH` +
			`SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV` +
			`MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8` +
			`NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",` +
			`"e":"AQAB",` +
			`"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I` +
			`jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0` +
			`BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn` +
			`439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT` +
			`CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh` +
			`BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",` +
			`"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi` +
			`YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG` +
			`BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",` +
			`"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa` +
			`ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA` +
			`-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",` +
			`"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q` +
			`CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb` +
			`34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",` +
			`"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa` +
			`7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky` +
			`NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",` +
			`"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o` +
			`y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU` +
			`W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		k := jwa.RS256.New().NewKey(key.PrivateKey, key.PublicKey)
		h := &Header{Algorithm: jwa.RS256, Type: "JWT"}
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		got, err := Sign(h, payload, k)
		if err != nil {
			t.Fatal(err)
		}

		// It is not same with Appendix A.2 because JOSE header is compact encoded here.
		want := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"HVeJTJBURMOJaxWlJmcYE9pnd2Encfn4iYlTS6c9zc0pg5nDpC3vgDkdblOSVu8s" +
			"OYXnCgfpfFxsUn8golAZD9VKZnmd7-Z3RT54aW12zDCLkZUsqKIe3yFSzLzPy-31" +
			"KXolCsqeQgXWnq_HT-gf9I3-FGRvik6ty-YfgjxLvJsgzHwzWWohemAWbfA6lSgZ" +
			"jPEScVMxLQ6z7Uda9BxT8alpUHbJhEbU_3becu_tezD7vsscYp8pPd52LRWMYYIE" +
			"NYApMx4XviHYPG1AIdEPq7TeVFXPBSf_Jops0LeT1B9pCI3IbuCa-Wd4hrhQM1V8" +
			"QaYzD6k11fesYCXZU35kxw"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	t.Run("RFC7515 Appendix A.5 Example Unsecured JWS", func(t *testing.T) {
		k := jwa.None.New().NewKey(nil, nil)
		h := &Header{Algorithm: jwa.None, Type: "JWT"}
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		got, err := Sign(h, payload, k)
		if err != nil {
			t.Fatal(err)
		}

		// It is not same with Appendix A.5 because JOSE header is compact encoded here.
		want := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"."
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})
}
