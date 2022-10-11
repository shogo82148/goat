package jwe

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/acbc" // for AES-CBC-HMAC-SHA2
	_ "github.com/shogo82148/goat/jwa/agcm" // for AES-GCM
	_ "github.com/shogo82148/goat/jwa/agcmkw"
	_ "github.com/shogo82148/goat/jwa/akw"
	_ "github.com/shogo82148/goat/jwa/pbes2"
	_ "github.com/shogo82148/goat/jwa/rsaoaep"
	_ "github.com/shogo82148/goat/jwa/rsapkcs1v15"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/keymanage"
)

func TestDecrypt(t *testing.T) {
	t.Run("RFC 7516 Appendix A.1.  Example JWE using RSAES-OAEP and AES GCM", func(t *testing.T) {
		raw := `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.` +
			`OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe` +
			`ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb` +
			`Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV` +
			`mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8` +
			`1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi` +
			`6UklfCpIMfIjf7iGdXKHzg.` +
			`48V1_ALb6US04U3b.` +
			`5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji` +
			`SdiwkIr3ajwQzaBtQD_A.` +
			`XFBoMYUZodetZdvTiFvSkQ`
		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{"kty":"RSA",` +
				`"n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW` +
				`cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S` +
				`psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a` +
				`sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS` +
				`tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj` +
				`YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",` +
				`"e":"AQAB",` +
				`"d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N` +
				`WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9` +
				`3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk` +
				`qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl` +
				`t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd` +
				`VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",` +
				`"p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-` +
				`SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf` +
				`fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",` +
				`"q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm` +
				`UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX` +
				`IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",` +
				`"dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL` +
				`hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827` +
				`rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",` +
				`"dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj` +
				`ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB` +
				`UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",` +
				`"qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7` +
				`AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3` +
				`eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := "The true sign of intelligence is not knowledge but imagination."
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	t.Run("RFC 7516 Appendix A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		raw := `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.` +
			`UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm` +
			`1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc` +
			`HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF` +
			`NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8` +
			`rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv` +
			`-B3oWh2TbqmScqXMR4gp_A.` +
			`AxY8DCtDaGlsbGljb3RoZQ.` +
			`KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.` +
			`9hH0vgRfYgPnAHOd8stkvw`

		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{"kty":"RSA",` +
				`"n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl` +
				`UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre` +
				`cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_` +
				`7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI` +
				`Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU` +
				`7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",` +
				`"e":"AQAB",` +
				`"d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq` +
				`1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry` +
				`nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_` +
				`0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj` +
				`-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj` +
				`T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",` +
				`"p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68` +
				`ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP` +
				`krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",` +
				`"q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y` +
				`BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN` +
				`-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",` +
				`"dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv` +
				`ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra` +
				`Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",` +
				`"dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff` +
				`7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_` +
				`odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",` +
				`"qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC` +
				`tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ` +
				`B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		want := "Live long and prosper."
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	t.Run("RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		raw := `eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.` +
			`6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.` +
			`AxY8DCtDaGlsbGljb3RoZQ.` +
			`KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.` +
			`U0m_YmjN04DJvceFICbCVQ`
		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{"kty":"oct",` +
				`"k":"GawgguFyGrWKav7AX4VKUg"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		want := "Live long and prosper."
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello JWE!' > input.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption A128GCMKW --content-encryption A128GCM --output - input.txt
	t.Run("jwx A128GCMKW", func(t *testing.T) {
		raw := `eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJnODc1b1pydUo1eWotUXFhIiwidGFnIjoieEtCdnR1cF81Szd1MWVFZzhXMjc4USJ9.` +
			`5V4E9fbfCuHzmHbwitHKeg.` +
			`JIFlyUcJ3cdSMABW.` +
			`p6YrKQpF8YA9nj4.` +
			`zaroAba3C8OJkX4l3DOjwg`
		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{` +
				`"k": "5zDzOzDfceBkTJHEec_s0g",` +
				`"kty": "oct"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := "Hello JWE!\n"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello World!' > payload.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption PBES2-HS256+A128KW --content-encryption A128GCM payload.txt
	t.Run("jwx PBES2-HS256+A128KW", func(t *testing.T) {
		raw := `eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjoxMDAwMCwicDJzIjoiT0RVTU5YOFR2cER0T3h5Q09GdThpZyJ9.` +
			`YxL8zZTWrXF9Wtw6yqCRWgtsajIR4Mf9.` +
			`16XfRbDsy7WLjmYD.` +
			`zY9HEtQPiMb5vyvJRA.` +
			`N9prznFZGKxHzjVzHzS2AQ`
		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{` +
				`"k": "uOnJO3TwtrVnA6QIKw3xXg",` +
				`"kty": "oct"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := "Hello World!\n"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello JWE!' > input.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --compress --key-encryption A128GCMKW --content-encryption A128GCM --output - input.txt
	t.Run("jwx A128GCMKW Compressed", func(t *testing.T) {
		raw := `eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJFZ3lkYnpXRDU4T19RbVVqIiwidGFnIjoiTWo2QXhXODQ2QkRKZGNQZy1rVGJGZyIsInppcCI6IkRFRiJ9.` +
			`YLGsDNVS-br9XTwXO_PUdA.` +
			`btLdyWp8CVr98RIV.` +
			`fIzbKm4IawNAl6AAzu-YXpE-24sy.` +
			`5X-zJCDW_KitFcRVqhCcbg`
		msg, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			rawKey := `{` +
				`"k": "5zDzOzDfceBkTJHEec_s0g",` +
				`"kty": "oct"` +
				`}`
			k, err := jwk.ParseKey([]byte(rawKey))
			if err != nil {
				return nil, err
			}
			alg := protected.Algorithm().New()
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := "Hello JWE!\n"
		if string(got) != want {
			t.Errorf("want %s, got %s", want, got)
		}
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("RFC 7516 Appendix A.1.  Example JWE using RSAES-OAEP and AES GCM", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW` +
			`cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S` +
			`psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a` +
			`sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS` +
			`tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj` +
			`YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",` +
			`"e":"AQAB",` +
			`"d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N` +
			`WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9` +
			`3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk` +
			`qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl` +
			`t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd` +
			`VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",` +
			`"p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-` +
			`SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf` +
			`fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",` +
			`"q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm` +
			`UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX` +
			`IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",` +
			`"dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL` +
			`hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827` +
			`rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",` +
			`"dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj` +
			`ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB` +
			`UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",` +
			`"qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7` +
			`AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3` +
			`eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}

		header := &Header{}
		header.SetAlgorithm(jwa.RSA_OAEP)
		alg := header.Algorithm().New()
		key := alg.NewKeyWrapper(k)

		plaintext := "The true sign of intelligence is not knowledge but imagination."
		msg1, err := NewMessage(jwa.A256GCM, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})

	t.Run("RFC 7516 Appendix A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl` +
			`UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre` +
			`cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_` +
			`7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI` +
			`Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU` +
			`7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",` +
			`"e":"AQAB",` +
			`"d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq` +
			`1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry` +
			`nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_` +
			`0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj` +
			`-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj` +
			`T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",` +
			`"p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68` +
			`ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP` +
			`krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",` +
			`"q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y` +
			`BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN` +
			`-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",` +
			`"dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv` +
			`ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra` +
			`Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",` +
			`"dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff` +
			`7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_` +
			`odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",` +
			`"qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC` +
			`tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ` +
			`B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		alg := jwa.RSA1_5.New()
		key := alg.NewKeyWrapper(k)

		header := &Header{}
		header.SetAlgorithm(jwa.RSA1_5)
		plaintext := "Live long and prosper."
		msg1, err := NewMessage(jwa.A128CBC_HS256, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})

	t.Run("RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256", func(t *testing.T) {
		rawKey := `{"kty":"oct",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		alg := jwa.A128KW.New()
		key := alg.NewKeyWrapper(k)

		header := &Header{}
		header.SetAlgorithm(jwa.A128KW)
		plaintext := "Live long and prosper."
		msg1, err := NewMessage(jwa.A128CBC_HS256, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello JWE!' > input.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption A128GCMKW --content-encryption A128GCM --output - input.txt
	t.Run("jwx A128GCMKW", func(t *testing.T) {
		rawKey := `{` +
			`"k": "5zDzOzDfceBkTJHEec_s0g",` +
			`"kty": "oct"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		header := &Header{}
		header.SetAlgorithm(jwa.A128GCMKW)
		alg := header.Algorithm().New()
		key := alg.NewKeyWrapper(k)
		plaintext := "Hello JWE!\n"
		msg1, err := NewMessageWithKW(jwa.A128GCM, key, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello World!' > payload.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --key-encryption PBES2-HS256+A128KW --content-encryption A128GCM payload.txt
	t.Run("jwx PBES2-HS256+A128KW", func(t *testing.T) {
		rawKey := `{` +
			`"k": "uOnJO3TwtrVnA6QIKw3xXg",` +
			`"kty": "oct"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		header := &Header{}
		header.SetAlgorithm(jwa.PBES2_HS256_A128KW)
		alg := header.Algorithm().New()
		key := alg.NewKeyWrapper(k)
		plaintext := "Hello World!\n"
		msg1, err := NewMessageWithKW(jwa.A128GCM, key, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})

	// https://github.com/lestrrat-go/jwx
	// $ echo 'Hello JWE!' > input.txt
	// $ jwx jwk generate --type oct --keysize 16 > oct.json
	// $ jwx jwe encrypt --key oct.json --compress --key-encryption A128GCMKW --content-encryption A128GCM --output - input.txt
	t.Run("jwx A128GCMKW compressed", func(t *testing.T) {
		rawKey := `{` +
			`"k": "5zDzOzDfceBkTJHEec_s0g",` +
			`"kty": "oct"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		header := &Header{}
		header.SetAlgorithm(jwa.A128GCMKW)
		header.SetCompressionAlgorithm(jwa.DEF)
		alg := header.Algorithm().New()
		key := alg.NewKeyWrapper(k)
		plaintext := "Hello JWE!\n"
		msg1, err := NewMessageWithKW(jwa.A128GCM, key, header, []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		err = msg1.Encrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}

		ciphertext, err := msg1.Compact()
		if err != nil {
			t.Fatal(err)
		}

		msg2, err := Parse(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := msg2.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
			return alg.NewKeyWrapper(k), nil
		}))
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != plaintext {
			t.Errorf("want %s, got %s", plaintext, got)
		}
	})
}

func TestParseJSON(t *testing.T) {
	raw := `{` +
		`"protected":` +
		`"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",` +
		`"unprotected":` +
		`{"jku":"https://server.example.com/keys.jwks"},` +
		`"recipients":[` +
		`{"header":` +
		`{"alg":"RSA1_5","kid":"2011-04-29"},` +
		`"encrypted_key":` +
		`"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-` +
		`kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx` +
		`GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3` +
		`YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh` +
		`cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg` +
		`wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},` +
		`{"header":` +
		`{"alg":"A128KW","kid":"7"},` +
		`"encrypted_key":` +
		`"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],` +
		`"iv":` +
		`"AxY8DCtDaGlsbGljb3RoZQ",` +
		`"ciphertext":` +
		`"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",` +
		`"tag":` +
		`"Mz-VPPyU4RlcuYv1IwIvzw"` +
		`}`
	msg, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
		if recipient.KeyID() != "2011-04-29" {
			return nil, errors.New("key not found")
		}
		rawKey := `{"kty":"RSA",` +
			`"n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl` +
			`UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre` +
			`cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_` +
			`7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI` +
			`Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU` +
			`7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",` +
			`"e":"AQAB",` +
			`"d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq` +
			`1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry` +
			`nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_` +
			`0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj` +
			`-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj` +
			`T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",` +
			`"p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68` +
			`ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP` +
			`krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",` +
			`"q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y` +
			`BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN` +
			`-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",` +
			`"dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv` +
			`ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra` +
			`Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",` +
			`"dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff` +
			`7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_` +
			`odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",` +
			`"qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC` +
			`tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ` +
			`B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			return nil, err
		}
		alg := recipient.Algorithm().New()
		return alg.NewKeyWrapper(k), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := "Live long and prosper."
	if string(got) != want {
		t.Errorf("want %s, got %s", want, got)
	}

	got, err = msg.Decrypt(FindKeyWrapperFunc(func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
		if recipient.KeyID() != "7" {
			return nil, errors.New("key not found")
		}
		rawKey := `{"kty":"oct",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"` +
			`}`
		k, err := jwk.ParseKey([]byte(rawKey))
		if err != nil {
			return nil, err
		}
		alg := recipient.Algorithm().New()
		return alg.NewKeyWrapper(k), nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	want = "Live long and prosper."
	if string(got) != want {
		t.Errorf("want %s, got %s", want, got)
	}

	var jsonData map[string]any
	if err := json.Unmarshal([]byte(raw), &jsonData); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(jsonData)
	if err != nil {
		t.Fatal(err)
	}
	data, err := msg.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, data) {
		t.Errorf("want %s, got %s", canonical, data)
	}
}
