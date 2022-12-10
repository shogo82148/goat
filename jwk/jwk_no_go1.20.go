//go:build !go1.20

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
)

type ecdhPrivateKey struct{}
type ecdhPublicKey struct{}

// NewPrivateKey returns a new JWK from the private key.
//
// key must be one of [*crypto/ecdsa.PrivateKey], [*crypto/rsa.PrivateKey], [crypto/ed25519.PrivateKey],
// [x25519.PrivateKey], [ed448.PrivateKey], [x448.PrivateKey], or []byte.
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
// key must be one of [*crypto/ecdsa.PublicKey], [*crypto/rsa.PublicKey], [crypto/ed25519.PublicKey],
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
	panic("must not reach")
}
