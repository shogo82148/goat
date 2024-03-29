package jws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/eddsa" // for Ed25519
	_ "github.com/shogo82148/goat/jwa/es"    // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"    // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/none"  // for none
	_ "github.com/shogo82148/goat/jwa/rs"    // for RSASSA-PKCS1-v1_5 SHA-256
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

func TestVerify(t *testing.T) {
	t.Run("RFC 7515 Appendix A.1 Example JWS Using HMAC SHA-256", func(t *testing.T) {
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
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.HS256},
			KeyFinder:         &JWKKeyFinder{JWK: key},
		}

		msg, err := ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.HS256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}
		if want, got := "JWT", header.Type(); want != got {
			t.Errorf("unexpected type: want %s, got %s", want, got)
		}

		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 7515 Appendix A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256", func(t *testing.T) {
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
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.RS256},
			KeyFinder:         &JWKKeyFinder{JWK: key},
		}

		msg, err := ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.RS256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 7515 Appendix A.3 Example JWS Using ECDSA P-256 SHA-256", func(t *testing.T) {
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
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.ES256},
			KeyFinder:         &JWKKeyFinder{JWK: key},
		}

		msg, err := ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.ES256; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 7515 Appendix A.4 Example JWS Using ECDSA P-521 SHA-512", func(t *testing.T) {
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
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.ES512},
			KeyFinder:         &JWKKeyFinder{JWK: key},
		}

		msg, err := ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.ES512; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		want := []byte(`Payload`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 7515 Appendix A.5 Example Unsecured JWS", func(t *testing.T) {
		raw := []byte(
			"eyJhbGciOiJub25lIn0" +
				"." +
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				".",
		)
		msg, err := ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.None},
			KeyFinder: FindKeyFunc(func(ctx context.Context, header, _ *Header) (sig.SigningKey, error) {
				return header.Algorithm().New().NewSigningKey(nil), nil
			}),
		}

		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.None; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 8037 Appendix A.4 Ed25519 Validation", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.EdDSA},
			KeyFinder:         &JWKKeyFinder{JWK: key},
		}

		raw := "eyJhbGciOiJFZERTQSJ9" +
			"." +
			"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
			"." +
			"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
			"9g7sVvpAr_MuM0KAg"
		msg, err := ParseCompact([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		header, _, payload, err := v.Verify(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := header.Algorithm(), jwa.EdDSA; want != got {
			t.Errorf("unexpected algorithm: want %s, got %s", want, got)
		}

		want := "Example of Ed25519 signing"
		if string(payload) != want {
			t.Errorf("unexpected payload: want %q, got %q", want, string(payload))
		}
	})
}

func TestUnmarshalJSON(t *testing.T) {
	t.Run("RFC 7515 Appendix A.6. Example JWS Using General JWS JSON Serialization", func(t *testing.T) {
		raw := `{` +
			`"payload":` +
			`"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF` +
			`tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",` +
			`"signatures":[` +
			`{"protected":"eyJhbGciOiJSUzI1NiJ9",` +
			`"header":` +
			`{"kid":"2010-12-29"},` +
			`"signature":` +
			`"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ` +
			`mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb` +
			`KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl` +
			`b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES` +
			`c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX` +
			`LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},` +
			`{"protected":"eyJhbGciOiJFUzI1NiJ9",` +
			`"header":` +
			`{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},` +
			`"signature":` +
			`"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS` +
			`lSApmWQxfKTUJqPP3-Kg6NU1Q"}]` +
			`}`
		var msg Message
		if err := msg.UnmarshalJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}

		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.RS256},
			KeyFinder: FindKeyFunc(func(_ context.Context, protected, header *Header) (sig.SigningKey, error) {
				if header.KeyID() != "2010-12-29" {
					return nil, errors.New("unknown key id")
				}
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
					return nil, err
				}
				return protected.Algorithm().New().NewSigningKey(key), nil
			}),
		}
		_, _, payload, err := v.Verify(context.Background(), &msg)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}

		v = &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.ES256},
			KeyFinder: FindKeyFunc(func(_ context.Context, protected, header *Header) (sig.SigningKey, error) {
				if header.KeyID() != "e9bc097a-ce51-4036-9562-d2ade882db0d" {
					return nil, errors.New("unknown key id")
				}
				rawKey := `{"kty":"EC",` +
					`"crv":"P-256",` +
					`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
					`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
					`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
					`}`
				key, err := jwk.ParseKey([]byte(rawKey))
				if err != nil {
					return nil, err
				}
				return protected.Algorithm().New().NewSigningKey(key), nil
			}),
		}
		_, _, payload, err = v.Verify(context.Background(), &msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	t.Run("RFC 7515 Appendix A.7. Example JWS Using Flattened JWS JSON Serialization", func(t *testing.T) {
		raw := `{` +
			`"payload":` +
			`"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF` +
			`tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",` +
			`"protected":"eyJhbGciOiJFUzI1NiJ9",` +
			`"header":` +
			`{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},` +
			`"signature":` +
			`"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS` +
			`lSApmWQxfKTUJqPP3-Kg6NU1Q"` +
			`}`
		var msg Message
		if err := msg.UnmarshalJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.ES256},
			KeyFinder: FindKeyFunc(func(_ context.Context, protected, header *Header) (sig.SigningKey, error) {
				if header.KeyID() != "e9bc097a-ce51-4036-9562-d2ade882db0d" {
					return nil, errors.New("unknown key id")
				}
				rawKey := `{"kty":"EC",` +
					`"crv":"P-256",` +
					`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
					`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
					`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
					`}`
				key, err := jwk.ParseKey([]byte(rawKey))
				if err != nil {
					return nil, err
				}
				return protected.Algorithm().New().NewSigningKey(key), nil
			}),
		}
		_, _, payload, err := v.Verify(context.Background(), &msg)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})

	// test for b64 header parameter.
	t.Run("RFC 7797 Section 4.2. Example with Header Parameters", func(t *testing.T) {
		raw := `{` +
			`"protected":` +
			`"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",` +
			`"payload":` +
			`"$.02",` +
			`"signature":` +
			`"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"` +
			`}`
		var msg Message
		if err := msg.UnmarshalJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		v := &Verifier{
			AlgorithmVerifier: AllowedAlgorithms{jwa.HS256},
			KeyFinder: FindKeyFunc(func(_ context.Context, protected, header *Header) (sig.SigningKey, error) {
				rawKey := `{` +
					`"kty":"oct",` +
					`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
					`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
					`}`
				key, err := jwk.ParseKey([]byte(rawKey))
				if err != nil {
					return nil, err
				}
				return protected.Algorithm().New().NewSigningKey(key), nil
			}),
		}
		_, _, payload, err := v.Verify(context.Background(), &msg)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte(`$.02`)
		if !bytes.Equal(payload, want) {
			t.Errorf("unexpected payload: want %q, got %q", string(want), string(payload))
		}
	})
}

func TestMarshalJSON(t *testing.T) {
	t.Run("RFC 7515 Appendix A.6. Example JWS Using General JWS JSON Serialization", func(t *testing.T) {
		msg := NewMessage([]byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`))

		protected1 := NewHeader()
		protected1.SetAlgorithm(jwa.RS256)
		header1 := NewHeader()
		header1.SetKeyID("2010-12-29")
		rawKey1 := `{"kty":"RSA",` +
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
		key1, err := jwk.ParseKey([]byte(rawKey1))
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(protected1, header1, jwa.RS256.New().NewSigningKey(key1)); err != nil {
			t.Fatal(err)
		}

		protected := NewHeader()
		protected.SetAlgorithm(jwa.ES256)
		header := NewHeader()
		header.SetKeyID("e9bc097a-ce51-4036-9562-d2ade882db0d")
		rawKey2 := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
			`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
			`}`
		key2, err := jwk.ParseKey([]byte(rawKey2))
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(protected, header, jwa.ES256.New().NewSigningKey(key2)); err != nil {
			t.Fatal(err)
		}

		data, err := msg.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		var tmp any
		if err := json.Unmarshal(data, &tmp); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RFC 7515 Appendix A.7. Example JWS Using Flattened JWS JSON Serialization", func(t *testing.T) {
		msg := NewMessage([]byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`))

		protected2 := NewHeader()
		protected2.SetAlgorithm(jwa.ES256)
		header2 := NewHeader()
		header2.SetKeyID("e9bc097a-ce51-4036-9562-d2ade882db0d")
		rawKey2 := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
			`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
			`}`
		key2, err := jwk.ParseKey([]byte(rawKey2))
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(protected2, header2, jwa.ES256.New().NewSigningKey(key2)); err != nil {
			t.Fatal(err)
		}

		data, err := msg.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}

		var tmp any
		if err := json.Unmarshal(data, &tmp); err != nil {
			t.Fatal(err)
		}
	})

	// test for b64 header parameter.
	t.Run("RFC 7797 Section 4.2. Example with Header Parameters", func(t *testing.T) {
		msg := NewRawMessage([]byte("$.02"))
		header := NewHeader()
		header.SetAlgorithm(jwa.HS256)
		header.SetBase64(false)

		rawKey := `{` +
			`"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}

		if err := msg.Sign(header, nil, jwa.HS256.New().NewSigningKey(key)); err != nil {
			t.Fatal(err)
		}

		got, err := msg.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want := `{` +
			`"payload":` +
			`"$.02",` +
			`"protected":` +
			`"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",` +
			`"signature":` +
			`"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"` +
			`}`
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})
}

func TestSign(t *testing.T) {
	t.Run("RFC 7515 Appendix A.1 Example JWS Using HMAC SHA-256", func(t *testing.T) {
		rawKey := `{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		k := jwa.HS256.New().NewSigningKey(key)
		h := NewHeader()
		h.SetAlgorithm(jwa.HS256)
		h.SetType("JWT")
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		msg := NewMessage(payload)
		if err := msg.Sign(h, nil, k); err != nil {
			t.Fatal(err)
		}
		got, err := msg.Compact()
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

	t.Run("RFC 7515 Appendix A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256", func(t *testing.T) {
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
		k := jwa.RS256.New().NewSigningKey(key)
		h := NewHeader()
		h.SetAlgorithm(jwa.RS256)
		h.SetType("JWT")
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		msg := NewMessage(payload)
		if err := msg.Sign(h, nil, k); err != nil {
			t.Fatal(err)
		}
		got, err := msg.Compact()
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

	t.Run("RFC 7515 Appendix A.5 Example Unsecured JWS", func(t *testing.T) {
		h := NewHeader()
		h.SetAlgorithm(jwa.None)
		h.SetType("JWT")
		payload := []byte(`{"iss":"joe",` + "\r\n" +
			` "exp":1300819380,` + "\r\n" +
			` "http://example.com/is_root":true}`)
		k := jwa.None.New().NewSigningKey(nil)
		msg := NewMessage(payload)
		if err := msg.Sign(h, nil, k); err != nil {
			t.Fatal(err)
		}
		got, err := msg.Compact()
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

	t.Run("RFC 7797 Section 4.2. Example with Header Parameter", func(t *testing.T) {
		rawKey := `{` +
			`"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
			`}`
		key, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		k := jwa.HS256.New().NewSigningKey(key)
		h := NewHeader()
		h.SetAlgorithm(jwa.HS256)
		h.SetBase64(false)
		msg := NewRawMessage([]byte("$.02"))
		if err := msg.Sign(h, nil, k); err != nil {
			t.Fatal(err)
		}
		got, err := msg.Compact()
		if err != nil {
			t.Fatal(err)
		}
		want := "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
			"." +
			"." +
			"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})
}

func TestKeyTypeMissmatch(t *testing.T) {
	// from RFC 7515 Appendix A.3 Example JWS Using ECDSA P-256 SHA-256
	raw := []byte(
		"eyJhbGciOiJFUzI1NiJ9" + // {"alg":"ES256"}
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
			"pmWQxfKTUJqPP3-Kg6NU1Q",
	)

	// RFC 7517 A.1. Example Public Keys (RSA)
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
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{
		AlgorithmVerifier: AllowedAlgorithms{jwa.ES256},
		KeyFinder:         &JWKKeyFinder{JWK: key},
	}
	msg, err := ParseCompact(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = v.Verify(context.Background(), msg)
	if err == nil {
		t.Error("want error, got nil")
	}
}
