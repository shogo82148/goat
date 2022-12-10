//go:build go1.20

package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
)

type ecdhPrivateKey = ecdh.PrivateKey
type ecdhPublicKey = ecdh.PublicKey

// NewPrivateKey returns a new JWK from the private key.
//
// key must be one of [*crypto/ecdsa.PrivateKey], [*crypto/rsa.PrivateKey], [crypto/ed25519.PrivateKey], [*crypto/ecdh.PrivateKey],
// [x25519.PrivateKey], [ed448.PrivateKey],
// [x448.PrivateKey] or []byte.
func NewPrivateKey(key crypto.PrivateKey) (*Key, error) {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		if err := validateEcdsaPrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.EC,
			priv: key,
			pub:  key.Public(),
		}, nil
	case *rsa.PrivateKey:
		if err := validateRSAPrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.RSA,
			priv: key,
			pub:  key.Public(),
		}, nil
	case ed25519.PrivateKey:
		if err := validateEd25519PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case *ecdh.PrivateKey:
		switch key.Curve() {
		case ecdh.P256(), ecdh.P384(), ecdh.P521():
			return &Key{
				kty: jwa.EC,
				keyOps: []jwktypes.KeyOp{
					jwktypes.KeyOpDeriveKey,
					jwktypes.KeyOpDeriveBits,
				},
				priv: key,
				pub:  key.PublicKey(),
			}, nil
		case ecdh.X25519():
			return &Key{
				kty: jwa.OKP,
				keyOps: []jwktypes.KeyOp{
					jwktypes.KeyOpDeriveKey,
					jwktypes.KeyOpDeriveBits,
				},
				priv: key,
				pub:  key.PublicKey(),
			}, nil
		default:
			return nil, fmt.Errorf("jwk: unknown ecdh curve: %s", key.Curve())
		}
	case x25519.PrivateKey:
		if err := validateX25519PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case ed448.PrivateKey:
		if err := validateEd448PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case x448.PrivateKey:
		if err := validateX448PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case []byte:
		return &Key{
			kty:  jwa.Oct,
			priv: append([]byte(nil), key...),
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}
}

// NewPublicKey returns a new JWK from the public key.
//
// key must be one of [*crypto/ecdsa.PublicKey], [*crypto/rsa.PublicKey], [crypto/ed25519.PublicKey], [*crypto/ecdh.PublicKey],
// [x25519.PublicKey], [ed448.PublicKey], [x448.PublicKey].
func NewPublicKey(key crypto.PublicKey) (*Key, error) {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		if err := validateEcdsaPublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.EC,
			pub: key,
		}, nil
	case *rsa.PublicKey:
		if err := validateRSAPublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.RSA,
			pub: key,
		}, nil
	case ed25519.PublicKey:
		if err := validateEd25519PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case *ecdh.PublicKey:
		switch key.Curve() {
		case ecdh.P256(), ecdh.P384(), ecdh.P521():
			return &Key{
				kty:    jwa.EC,
				keyOps: []jwktypes.KeyOp{jwktypes.KeyOpDeriveBits},
				pub:    key,
			}, nil
		case ecdh.X25519():
			return &Key{
				kty:    jwa.OKP,
				keyOps: []jwktypes.KeyOp{jwktypes.KeyOpDeriveBits},
				pub:    key,
			}, nil
		default:
			return nil, fmt.Errorf("jwk: unknown ecdh curve: %s", key.Curve())
		}
	case x25519.PublicKey:
		if err := validateX25519PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case ed448.PublicKey:
		if err := validateEd448PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case x448.PublicKey:
		if err := validateX448PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown public key type: %T", key)
	}
}

func encodeECDHKey(e *jsonutils.Encoder, priv *ecdhPrivateKey, pub *ecdhPublicKey) {
	switch pub.Curve() {
	case ecdh.P256():
		e.Set("kty", jwa.EC.String())
		e.Set("crv", jwa.P256.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:32+1])
		e.SetBytes("y", data[32+1:])
	case ecdh.P384():
		e.Set("kty", jwa.EC.String())
		e.Set("crv", jwa.P384.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:48+1])
		e.SetBytes("y", data[48+1:])
	case ecdh.P521():
		e.Set("kty", jwa.EC.String())
		e.Set("crv", jwa.P521.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:66+1])
		e.SetBytes("y", data[66+1:])
	case ecdh.X25519():
		e.Set("kty", jwa.OKP)
		e.Set("crv", jwa.Ed25519.String())
		e.SetBytes("x", pub.Bytes())
	}

	if priv != nil {
		e.SetBytes("d", priv.Bytes())
	}
}
