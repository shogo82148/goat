package jwe

import (
	"reflect"
	"testing"
)

func FuzzJWECompact(f *testing.F) {
	// RFC 7516 Appendix A.1.  Example JWE using RSAES-OAEP and AES GCM
	f.Add(`eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.` +
		`OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe` +
		`ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb` +
		`Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV` +
		`mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8` +
		`1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi` +
		`6UklfCpIMfIjf7iGdXKHzg.` +
		`48V1_ALb6US04U3b.` +
		`5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji` +
		`SdiwkIr3ajwQzaBtQD_A.` +
		`XFBoMYUZodetZdvTiFvSkQ`)

	// RFC 7516 Appendix A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
	f.Add(`eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.` +
		`UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm` +
		`1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc` +
		`HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF` +
		`NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8` +
		`rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv` +
		`-B3oWh2TbqmScqXMR4gp_A.` +
		`AxY8DCtDaGlsbGljb3RoZQ.` +
		`KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.` +
		`9hH0vgRfYgPnAHOd8stkvw`)

	// RFC 7516 Appendix A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
	f.Add(`eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.` +
		`6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.` +
		`AxY8DCtDaGlsbGljb3RoZQ.` +
		`KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.` +
		`U0m_YmjN04DJvceFICbCVQ`)

	// https://github.com/lestrrat-go/jwx
	f.Add(`eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJnODc1b1pydUo1eWotUXFhIiwidGFnIjoieEtCdnR1cF81Szd1MWVFZzhXMjc4USJ9.` +
		`5V4E9fbfCuHzmHbwitHKeg.` +
		`JIFlyUcJ3cdSMABW.` +
		`p6YrKQpF8YA9nj4.` +
		`zaroAba3C8OJkX4l3DOjwg`)
	f.Add(`eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjoxMDAwMCwicDJzIjoiT0RVTU5YOFR2cER0T3h5Q09GdThpZyJ9.` +
		`YxL8zZTWrXF9Wtw6yqCRWgtsajIR4Mf9.` +
		`16XfRbDsy7WLjmYD.` +
		`zY9HEtQPiMb5vyvJRA.` +
		`N9prznFZGKxHzjVzHzS2AQ`)

	f.Fuzz(func(t *testing.T, s string) {
		msg0, err := Parse([]byte(s))
		if err != nil {
			return
		}
		data, err := msg0.Compact()
		if err != nil {
			t.Error(err)
		}
		msg, err := Parse(data)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(msg, msg0) {
			t.Errorf("mismatch")
		}
	})
}

func FuzzJWEJSON(f *testing.F) {
	f.Add(`{` +
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
		`}`)
	f.Fuzz(func(t *testing.T, raw string) {
		msg, err := ParseJSON([]byte(raw))
		if err != nil {
			return
		}
		data, err := msg.MarshalJSON()
		if err != nil {
			t.Error(err)
			return
		}
		_, err = ParseJSON(data)
		if err != nil {
			t.Error(err)
			return
		}
	})
}
