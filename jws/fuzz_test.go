package jws

import (
	"bytes"
	"context"
	"errors"
	"testing"

	_ "github.com/shogo82148/goat/jwa/eddsa" // for Ed25519
	_ "github.com/shogo82148/goat/jwa/es"    // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"    // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/rs"    // for RSASSA-PKCS1-v1_5 SHA-256
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

var jwsPayloads = []string{
	// JWS protected by RSA Key and EC Key
	`{` +
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
		`}`,

	// JWS protected by EC Key
	`{` +
		`"payload":` +
		`"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF` +
		`tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",` +
		`"protected":"eyJhbGciOiJFUzI1NiJ9",` +
		`"header":` +
		`{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},` +
		`"signature":` +
		`"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS` +
		`lSApmWQxfKTUJqPP3-Kg6NU1Q"` +
		`}`,

	// JWS protected by Oct Key
	`{` +
		`"protected":` +
		`"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",` +
		`"payload":` +
		`"$.02",` +
		`"signature":` +
		`"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"` +
		`}`,
}

func NewFuzzJWSFunc(key *jwk.Key) func(t *testing.T, data string) {
	return func(t *testing.T, data string) {
		var sigKey sig.SigningKey
		v1 := &Verifier{
			AlgorithmVerifier: UnsecureAnyAlgorithm,
			KeyFinder: FindKeyFunc(func(_ context.Context, header, _ *Header) (sig.SigningKey, error) {
				alg := header.Algorithm()
				if !alg.Available() {
					return nil, errors.New("unknown algorithm")
				}
				sigKey = alg.New().NewSigningKey(key)
				return sigKey, nil
			}),
		}

		msg1, err := ParseCompact([]byte(data))
		if err != nil {
			return
		}
		header1, _, payload1, err := v1.Verify(context.Background(), msg1)
		if err != nil {
			return
		}
		if key.PrivateKey() == nil {
			return // the key doesn't support signing, we skip it.
		}

		msg2 := NewMessage(payload1)
		if err := msg2.Sign(header1, nil, sigKey); err != nil {
			t.Error(err)
		}
		resigned, err := msg2.Compact()
		if err != nil {
			t.Error(err)
		}

		v2 := &Verifier{
			AlgorithmVerifier: UnsecureAnyAlgorithm,
			KeyFinder: FindKeyFunc(func(_ context.Context, header, _ *Header) (sig.SigningKey, error) {
				return sigKey, nil
			}),
		}
		msg3, err := ParseCompact(resigned)
		if err != nil {
			t.Fatal(err)
		}
		_, _, payload3, err := v2.Verify(context.Background(), msg3)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(payload1, payload3) {
			t.Error("payload mismatch")
		}
	}
}

func FuzzJWS_RSAKey(f *testing.F) {
	for _, payload := range jwsPayloads {
		f.Add(payload)
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
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSFunc(key))
}
func FuzzJWS_ECKey(f *testing.F) {
	for _, payload := range jwsPayloads {
		f.Add(payload)
	}

	rawKey := `{"kty":"EC",` +
		`"crv":"P-256",` +
		`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
		`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
		`}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSFunc(key))
}

func FuzzJWS_OctKey(f *testing.F) {
	for _, payload := range jwsPayloads {
		f.Add(payload)
	}

	rawKey := `{` +
		`"kty":"oct",` +
		`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
		`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
		`}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSFunc(key))
}

var jwsCompactPayloads = []string{
	// JWS Compact protected by Oct Key
	"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",

	// JWS Compact protected by RSA Key
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

	// JWS Compact protected by EC P-256 Key
	"eyJhbGciOiJFUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q",

	// JWS Compact protected by EC P-521 Key
	"eyJhbGciOiJFUzUxMiJ9" +
		"." +
		"UGF5bG9hZA" +
		"." +
		"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq" +
		"wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp" +
		"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",

	// JWS Compact protected by Ed25519 Key
	"eyJhbGciOiJFZERTQSJ9" +
		"." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		"." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt" +
		"9g7sVvpAr_MuM0KAg",
}

func NewFuzzJWSCompactFunc(key *jwk.Key) func(t *testing.T, data string) {
	return func(t *testing.T, data string) {
		var sigKey sig.SigningKey
		v1 := &Verifier{
			AlgorithmVerifier: UnsecureAnyAlgorithm,
			KeyFinder: FindKeyFunc(func(_ context.Context, header, _ *Header) (sig.SigningKey, error) {
				alg := header.Algorithm()
				if !alg.Available() {
					return nil, errors.New("unknown algorithm")
				}
				sigKey = alg.New().NewSigningKey(key)
				return sigKey, nil
			}),
		}

		msg1, err := ParseCompact([]byte(data))
		if err != nil {
			return
		}
		header1, _, payload1, err := v1.Verify(context.Background(), msg1)
		if err != nil {
			return
		}
		if key.PrivateKey() == nil {
			return // the key doesn't support signing, we skip it.
		}

		msg2 := NewMessage(payload1)
		if err := msg2.Sign(header1, nil, sigKey); err != nil {
			t.Error(err)
		}
		resigned, err := msg2.Compact()
		if err != nil {
			t.Error(err)
		}

		v2 := &Verifier{
			AlgorithmVerifier: UnsecureAnyAlgorithm,
			KeyFinder: FindKeyFunc(func(_ context.Context, header, _ *Header) (sig.SigningKey, error) {
				return sigKey, nil
			}),
		}
		msg3, err := ParseCompact(resigned)
		if err != nil {
			t.Fatal(err)
		}
		_, _, payload3, err := v2.Verify(context.Background(), msg3)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(payload1, payload3) {
			t.Error("payload mismatch")
		}
	}
}

func FuzzJWSCompact_RSAKey(f *testing.F) {
	for _, payload := range jwsCompactPayloads {
		f.Add(payload)
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
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSCompactFunc(key))
}

func FuzzJWSCompact_EC_P256(f *testing.F) {
	for _, payload := range jwsCompactPayloads {
		f.Add(payload)
	}

	rawKey := `{"kty":"EC",` +
		`"crv":"P-256",` +
		`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
		`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
		`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
		`}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSCompactFunc(key))
}

func FuzzJWSCompact_EC_P521(f *testing.F) {
	for _, payload := range jwsCompactPayloads {
		f.Add(payload)
	}

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
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSCompactFunc(key))
}

func FuzzJWSCompact_Ed25519(f *testing.F) {
	for _, payload := range jwsCompactPayloads {
		f.Add(payload)
	}

	rawKey := `{"kty":"OKP","crv":"Ed25519",` +
		`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSCompactFunc(key))
}

func FuzzJWSCompact_OctKey(f *testing.F) {
	for _, payload := range jwsCompactPayloads {
		f.Add(payload)
	}

	rawKey := `{"kty":"oct",` +
		`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
		`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"` +
		`}`
	key, err := jwk.ParseKey([]byte(rawKey))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(NewFuzzJWSCompactFunc(key))
}
