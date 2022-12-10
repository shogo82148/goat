//go:build go1.20

package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/shogo82148/goat/jwa"
)

func TestNewPrivateKey_ECDH(t *testing.T) {
	for _, crv := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(crv.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(crv, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			privECDH, err := priv.ECDH()
			if err != nil {
				t.Fatal(err)
			}
			key0, err := NewPrivateKey(privECDH)
			if err != nil {
				t.Fatal(err)
			}
			data, err := key0.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			key1, err := ParseKey(data)
			if err != nil {
				t.Fatal(err)
			}
			if !priv.Equal(key1.PrivateKey()) {
				t.Error("key not match")
			}
		})
	}
	t.Run("X25519", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.OKP {
			t.Errorf("unexpected type type: got %s, want %s", key.kty, jwa.OKP)
		}
		if _, err := key.MarshalJSON(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNewPublicKey_ECDH(t *testing.T) {
	for _, crv := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(crv.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(crv, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub := &priv.PublicKey
			pubECDH, err := pub.ECDH()
			if err != nil {
				t.Fatal(err)
			}
			key0, err := NewPublicKey(pubECDH)
			if err != nil {
				t.Fatal(err)
			}
			data, err := key0.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			key1, err := ParseKey(data)
			if err != nil {
				t.Fatal(err)
			}
			if !pub.Equal(key1.PublicKey()) {
				t.Error("key not match")
			}
		})
	}

	t.Run("X25519", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(priv.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if key.kty != jwa.OKP {
			t.Errorf("unexpected type type: got %s, want %s", key.kty, jwa.OKP)
		}
		if _, err := key.MarshalJSON(); err != nil {
			t.Fatal(err)
		}
	})
}
