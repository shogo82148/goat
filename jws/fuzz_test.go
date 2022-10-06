package jws

import (
	"bytes"
	"errors"
	"testing"

	_ "github.com/shogo82148/goat/jwa/eddsa" // for Ed25519
	_ "github.com/shogo82148/goat/jwa/es"    // for ECDSA
	_ "github.com/shogo82148/goat/jwa/hs"    // for HMAC SHA-256
	_ "github.com/shogo82148/goat/jwa/rs"    // for RSASSA-PKCS1-v1_5 SHA-256
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

func FuzzJWS(f *testing.F) {
	f.Add(
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		`{"kty":"oct",`+
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75`+
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"`+
			`}`,
	)
	f.Add(
		"eyJhbGciOiJSUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"+
			"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"+
			"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"+
			"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"+
			"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"+
			"p0igcN_IoypGlUPQGe77Rw",
		`{"kty":"RSA",`+
			`"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx`+
			`HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs`+
			`D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH`+
			`SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV`+
			`MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8`+
			`NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",`+
			`"e":"AQAB",`+
			`"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I`+
			`jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0`+
			`BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn`+
			`439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT`+
			`CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh`+
			`BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",`+
			`"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi`+
			`YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG`+
			`BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",`+
			`"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa`+
			`ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA`+
			`-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",`+
			`"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q`+
			`CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb`+
			`34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",`+
			`"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa`+
			`7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky`+
			`NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",`+
			`"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o`+
			`y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU`+
			`W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"`+
			`}`,
	)
	f.Add(
		"eyJhbGciOiJFUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"+
			"pmWQxfKTUJqPP3-Kg6NU1Q",
		`{"kty":"EC",`+
			`"crv":"P-256",`+
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",`+
			`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",`+
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"`+
			`}`,
	)
	f.Add(
		"eyJhbGciOiJFUzUxMiJ9"+
			"."+
			"UGF5bG9hZA"+
			"."+
			"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq"+
			"wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp"+
			"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",
		`{"kty":"EC",`+
			`"crv":"P-521",`+
			`"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_`+
			`NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",`+
			`"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl`+
			`y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",`+
			`"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA`+
			`xerEzgdRhajnu0ferB0d53vM9mE15j2C"`+
			`}`,
	)
	f.Add(
		"eyJhbGciOiJFZERTQSJ9"+
			"."+
			"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"+
			"."+
			"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt"+
			"9g7sVvpAr_MuM0KAg",
		`{"kty":"OKP","crv":"Ed25519",`+
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",`+
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	)
	f.Fuzz(func(t *testing.T, data, key string) {
		k, err := jwk.ParseKey([]byte(key))
		if err != nil {
			return
		}
		var sigKey sig.Key
		msg1, err := Parse([]byte(data))
		if err != nil {
			return
		}
		header1, payload1, err := msg1.Verify(FindKeyFunc(func(header, _ *Header) (sig.Key, error) {
			alg := header.Algorithm()
			if !alg.Available() {
				return nil, errors.New("unknown algorithm")
			}
			sigKey = alg.New().NewKey(k.KeyPair())
			return sigKey, nil
		}))
		if err != nil {
			return
		}
		if k.PrivateKey() == nil {
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

		msg3, err := Parse(resigned)
		if err != nil {
			t.Fatal(err)
		}
		_, payload3, err := msg3.Verify(FindKeyFunc(func(header, _ *Header) (sig.Key, error) {
			return sigKey, nil
		}))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(payload1, payload3) {
			t.Error("payload mismatch")
		}
	})
}
