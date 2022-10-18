package jwk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
	"golang.org/x/crypto/ed25519"
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

func TestNewPrivateKey(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv, key.PrivateKey())
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv.PublicKey, key.PublicKey())
		}
	})

	t.Run("rsa", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv, key.PrivateKey())
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv.PublicKey, key.PublicKey())
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv, key.PrivateKey())
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})

	t.Run("x25519", func(t *testing.T) {
		pub, priv, err := x25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv, key.PrivateKey())
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})

	t.Run("x448", func(t *testing.T) {
		pub, priv, err := x448.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(key.PrivateKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv, key.PrivateKey())
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})

	t.Run("oct", func(t *testing.T) {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(buf)
		if err != nil {
			t.Fatal(err)
		}
		got := key.PrivateKey().([]byte)
		if !bytes.Equal(buf, got) {
			t.Errorf("unexpected PrivateKey: want %#v, got %#v", buf, got)
		}
	})
}

func TestNewPublicKey(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv.PublicKey, key.PublicKey())
		}
	})

	t.Run("rsa", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if !priv.PublicKey.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", priv.PublicKey, key.PublicKey())
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})

	t.Run("x25519", func(t *testing.T) {
		pub, _, err := x25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})

	t.Run("x448", func(t *testing.T) {
		pub, _, err := x448.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !pub.Equal(key.PublicKey()) {
			t.Errorf("unexpected PublicKey: want %#v, got %#v", pub, key.PublicKey())
		}
	})
}

func TestNewPublicKey_Invalid(t *testing.T) {
	t.Run("ecdsa: unsupported curve", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewPublicKey(priv.Public())
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("ecdsa: zero", func(t *testing.T) {
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int),
			Y:     new(big.Int),
		}
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("ecdsa: zero", func(t *testing.T) {
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(9223372036854775807),
			Y:     big.NewInt(9223372036854775807),
		}
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("rsa: invalid modulus", func(t *testing.T) {
		pub := &rsa.PublicKey{
			E: 65537,
		}
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("rsa: invalid public exponent", func(t *testing.T) {
		pub := &rsa.PublicKey{
			E: 1,
			N: new(big.Int),
		}
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("ed25519: invalid size", func(t *testing.T) {
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize-1)
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("x25519: invalid size", func(t *testing.T) {
		pub := make(x25519.PublicKey, x25519.PublicKeySize-1)
		_, err := NewPublicKey(pub)
		if err == nil {
			t.Error("want error, but got nil")
		}
	})

	t.Run("oct", func(t *testing.T) {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPublicKey(buf); err == nil {
			t.Error("want error, got nil")
		}
	})
}
