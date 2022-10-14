package jwk

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"testing"
)

func newBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("failed to parse " + s)
	}
	return n
}

func TestThumbprint(t *testing.T) {
	t.Run("RFC 7638 Section 3.1. Example JWK Thumbprint Computation", func(t *testing.T) {
		raw := `{` +
			`"kty": "RSA",` +
			`"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt` +
			`VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6` +
			`4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD` +
			`W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9` +
			`1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH` +
			`aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e": "AQAB",` +
			`"alg": "RS256",` +
			`"kid": "2011-04-29"` +
			`}`
		key, err := ParseKey([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		thumb, err := key.Thumbprint(sha256.New())
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{
			55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197,
			225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130,
			245, 123,
		}
		if subtle.ConstantTimeCompare(thumb, want) == 0 {
			t.Errorf("thumbprint mismatch: want %#v, got %#v", want, thumb)
		}
	})

	t.Run("RFC 8037 Appendix A.3. JWK Thumbprint Canonicalization", func(t *testing.T) {
		t.Run("private key", func(t *testing.T) {
			raw := `{"kty":"OKP","crv":"Ed25519",` +
				`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
				`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
			key, err := ParseKey([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			thumb, err := key.Thumbprint(sha256.New())
			if err != nil {
				t.Fatal(err)
			}
			want, _ := hex.DecodeString("90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89")
			if subtle.ConstantTimeCompare(thumb, want) == 0 {
				t.Errorf("thumbprint mismatch: want %#v, got %#v", want, thumb)
			}
		})
		t.Run("public key", func(t *testing.T) {
			raw := ` {"kty":"OKP","crv":"Ed25519",` +
				`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
			key, err := ParseKey([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			thumb, err := key.Thumbprint(sha256.New())
			if err != nil {
				t.Fatal(err)
			}
			want, _ := hex.DecodeString("90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89")
			if subtle.ConstantTimeCompare(thumb, want) == 0 {
				t.Errorf("thumbprint mismatch: want %#v, got %#v", want, thumb)
			}
		})
	})
}
