package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
)

func TestDecodePEM(t *testing.T) {
	t.Run("RSA Private Key", func(t *testing.T) {
		// openssl genrsa 2048
		// with LibreSSL 2.8.3
		raw := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvVYZweMca+b97pl03tCrwJ5RttScOiAvS+0QRdfEkxsRLO7o
alGjFV8g6RaFS1DxNtkQxn2NOgrjwEM32+HmTqoWMkEXeGLMi20UMrvAtRVXsLM3
Lkxi1FlEowPOgWCcJMM+C8lJPF/WwzfA2h7FU7EKzUPw/AjQbfhmOkYFmG/YHB7Z
+8PkJ6bzERnIMIorYnUYV8mV6k/KDadm5EkgaWPIcCvMH5ZoQaHWB3AfaMmudpmD
tYm9jG9XtOjQzp3zPV5AanO1IjU/EpKDQZ9rZWHLQERLckOFM5VBwmDNjKpe5g7p
efd9pq/ehMmPG2Exz+zoiksrvYJc2uWKsrMxBQIDAQABAoIBAEZ0OqN2YoYYb5eQ
zPd4yOClSRzyoqvSfCcRsQN8Ve6znMGOqTee50O1oWZ69eDf3tKdFWv3Hk1h7fwG
R0vwFKZjDl1m8Vff0+NyFJkIWp5HsdjT54236PLBwROz/+0OySu452a1YSYxN5Zv
Mbk4yA7ri2x0gsEWepDhZRD8K2rcVuYZpBbrlL5CGFn/Bm1QdkjmqExTxj7ndkrl
mU2MtlabytC/VUHGoLaaT8FP6TFpH++FRZTJCb4EUC+XMxpOvvhn8Ucljj5OwB6p
dgCpdvjUQHCAKmHa87G4iBA7wL2Rm/AqOkr/8poqkjqZLNdKB8/YSgWxTpm6mQHT
nDIqMiUCgYEA8+U3Cqv4smXGMzx+52ATJhGNR/JBemsqnu1zXS+9uXSv4Y9uE8B7
2ptEsegEriY9DLwcidxXuyiGKJFiMcZzOMLWuqolxzBD5vyIZiBbpZD8d58CjHLL
nY8OEaLKkyjaRCe9M9U682z2SRBD0WfDPnaktakxB3PtHYM0VrlgmjsCgYEAxrux
IHtvUx6n1ihRWZgC1vy6PiWkzSBgtSb8WN1TptRDsNTmAlhzF/4cfo/O7nLS0v8Y
1GoCzAjAO05nV5ov8VYgFZ34G/I0iz7+hzcgO4CdHhXVpScykFQrC0pdmvvKYMjQ
mOY0yrMFQWE2piauKFHmu1h8TMEoITiXqaGPbb8CgYEAy58TnAJFiNN1bPNV0+Af
PIos1ONJjWYJWFRQG32vPTVRXdS8hxsNjE5TROC7f5WHJKmsfeCLEkNb9mSigYH4
UmxAj+lbzvfZyPAPBIyBVzI7xbbojs+MdUeo7EpoLAJQb9Rpnuun4vGWkRtWM28Y
z36INu5Bc8JyNVCEEt+D6l8CgYEAk2nEQKju8gQKUTQE6+VzLc+3wsOflDzRH260
vqImG9jWAURa/SBo90IaFtNLltp7geGRpHaiboCLPzKwO2325BiTohVUZj5qNWPb
36bHdPu5EAj4OhJyUlbsuupFtuHQw6wR92jDfhv+6PlYVTTZ+LSP5yYCxdh9kO7u
qPhbcPcCgYBmaZiZSP5XCXFWHr8sxLu8Y3nLqLUpmzoZMe44ZbdyiPSHtdRMQrb1
zFxDB8XjbwaWEZH2hcbiucEam7ZMPJma/lagM2+gMFJ8SFD6VYj9ncxlx2OObUHr
e7N7lcOkhD9Ea2hZHQWff5fEh3PjbK64sVlsQ8itkwI85u/kzlhIOA==
-----END RSA PRIVATE KEY-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PrivateKey().(*rsa.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PrivateKey, got %T", key.PrivateKey())
		}
	})

	t.Run("RSA Public Key", func(t *testing.T) {
		raw := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvVYZweMca+b97pl03tCr
wJ5RttScOiAvS+0QRdfEkxsRLO7oalGjFV8g6RaFS1DxNtkQxn2NOgrjwEM32+Hm
TqoWMkEXeGLMi20UMrvAtRVXsLM3Lkxi1FlEowPOgWCcJMM+C8lJPF/WwzfA2h7F
U7EKzUPw/AjQbfhmOkYFmG/YHB7Z+8PkJ6bzERnIMIorYnUYV8mV6k/KDadm5Ekg
aWPIcCvMH5ZoQaHWB3AfaMmudpmDtYm9jG9XtOjQzp3zPV5AanO1IjU/EpKDQZ9r
ZWHLQERLckOFM5VBwmDNjKpe5g7pefd9pq/ehMmPG2Exz+zoiksrvYJc2uWKsrMx
BQIDAQAB
-----END PUBLIC KEY-----`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PublicKey().(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PrivateKey())
		}
	})

	t.Run("EC Private Key", func(t *testing.T) {
		// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
		// with OpenSSL 3.0.5
		raw := `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBmWYuWCk6KY7qdeeDj
txjpdRHJUWwksqz+7ZXKega08DLF7KcIIEi5Xy3C1imMCLihZANiAAQio9R+rQG3
Y1JSD0XSqN2fa9r+s/MjMUjAXsrvnYfDLGWEQc2Tov3ardE1sHwotMrBsgsdAP5G
uZtG8/RuOc1Sb+6Owna7WBOcMPwmJhmvnwRB68MI0d/4TEjUEgby0bg=
-----END PRIVATE KEY-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PrivateKey().(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want *ecdsa.PrivateKey, got %T", key.PrivateKey())
		}
	})

	t.Run("EC Public Key", func(t *testing.T) {
		raw := `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEIqPUfq0Bt2NSUg9F0qjdn2va/rPzIzFI
wF7K752HwyxlhEHNk6L92q3RNbB8KLTKwbILHQD+RrmbRvP0bjnNUm/ujsJ2u1gT
nDD8JiYZr58EQevDCNHf+ExI1BIG8tG4
-----END PUBLIC KEY-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *ecdsa.PublicKey, got %T", key.PrivateKey())
		}
	})

	t.Run("Ed25519 Private Key", func(t *testing.T) {
		// openssl genpkey -algorithm ED25519
		// with OpenSSL 3.0.5
		raw := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKwAUfUUia9rBpRD+sgNlTI5n5RhwMNDaaWFN5Kl3tiF
-----END PRIVATE KEY-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PrivateKey().(ed25519.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want ed25519.PrivateKey, got %T", key.PrivateKey())
		}
	})

	t.Run("Ed25519 Public Key", func(t *testing.T) {
		// openssl pkey -pubout < ed25519.key
		// with OpenSSL 3.0.5
		raw := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAvFC86jKoSVBrUVDYzf2ImVcNoIWfbugQuzAdCcvAZCU=
-----END PUBLIC KEY-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PublicKey().(ed25519.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want ed25519.PublicKey, got %T", key.PrivateKey())
		}
	})

	t.Run("certificate", func(t *testing.T) {
		raw := `-----BEGIN CERTIFICATE-----
MIICtjCCAZ4CCQC/u1cqvBzVVzANBgkqhkiG9w0BAQUFADAdMQswCQYDVQQGEwJK
UDEOMAwGA1UECAwFVG9reW8wHhcNMjIxMDE0MTIyOTM3WhcNMzIxMDExMTIyOTM3
WjAdMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC348Gl3COo5e1tz4rzROHo/OV1UNSF6DyXfhDK+QFt
t9oX/ENlEFWP97BYgE6qWuUdG7tPvW1VLXz08aP3L/67q0J0y3NWyppea5HrQEj9
79En8mXRl9HwbiiVMBqGmODny0G8Ju0LKzCncxBZ0pPbwlLFPccpXdGUbC8NMHnp
iK5W1+B0siqdxYqJgAze+CFAKr4PooDL+BUcxvaD0CHz3Zi521wMcLBosNT0vyet
thmiZxIY/2M3iAN7C62mA9cXJOGy/BWjckIi6i9KL2rvcK9fAWgvH/iyY1dSv5Vw
1m1+9blvk0w1MLDgayXXoP54C/y7/3wi1SSkCYWKndqdAgMBAAEwDQYJKoZIhvcN
AQEFBQADggEBABco5wpea6YQGBhN+DI11ck75IBxuM8bu/mpBdN+FCVnOoaMoMud
wk0Qbv/ogNp0C/R7tOzxdp98EzpX20dZ7u5PxDscmmLKVWA2A7VD6e7FPYEximVL
XAtmQbv4s3yvLVFiDQsLIEgA8syojQsVcX+YIKcmamTTL6R9tWcJpRxaJ5oZDGRf
dnNSurxxNf0vfyCZpszi+H53FypAs1U/jrsCBo8noTWloivF+yLy4msP9sfT6kC6
ivtuU8wX5zKB87h1/qCgEB5K4jqV6HEp7OzK8k/U7+2Of7RKK+qh+3+1WhBTmD1S
JKAyTyOUhqIPLBE1PPM8WyCFkFMpikYQxDc=
-----END CERTIFICATE-----
`
		key, _, err := DecodePEM([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := key.PublicKey().(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PrivateKey())
		}
	})
}
