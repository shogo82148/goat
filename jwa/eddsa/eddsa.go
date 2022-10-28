// Package eddsa is a signing algorithm Edwards-Curve Digital Signature Algorithm.
package eddsa

import (
	"crypto/ed25519"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

func New() sig.Algorithm {
	return &Algorithm{}
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.EdDSA, New)
}

type Algorithm struct{}

func (alg *Algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()
	canSign := jwktypes.CanUseFor(key, jwktypes.KeyOpSign)
	canVerify := jwktypes.CanUseFor(key, jwktypes.KeyOpVerify)

	switch priv := priv.(type) {
	case ed25519.PrivateKey:
		pubkey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return sig.NewInvalidKey("eddsa", priv, pub)
		}
		return &Ed25519{
			priv:      priv,
			pub:       pubkey,
			canSign:   canSign,
			canVerify: canVerify,
		}
	case ed448.PrivateKey:
		pubkey, ok := pub.(ed448.PublicKey)
		if !ok {
			return sig.NewInvalidKey("eddsa", priv, pub)
		}
		return &Ed448{
			priv:      priv,
			pub:       pubkey,
			canSign:   canSign,
			canVerify: canVerify,
		}
	case nil:
		switch pub := pub.(type) {
		case ed25519.PublicKey:
			return &Ed25519{
				pub:       pub,
				canSign:   canSign,
				canVerify: canVerify,
			}
		case ed448.PublicKey:
			return &Ed448{
				pub:       pub,
				canSign:   canSign,
				canVerify: canVerify,
			}
		default:
			return sig.NewInvalidKey("eddsa", priv, pub)
		}
	default:
		return sig.NewInvalidKey("eddsa", priv, pub)
	}
}

type Ed25519 struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	canSign   bool
	canVerify bool
}

func (key *Ed25519) Sign(payload []byte) (signature []byte, err error) {
	if !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed25519.Sign(key.priv, payload)
	return
}

func (key *Ed25519) Verify(payload, signature []byte) error {
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed25519.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}

type Ed448 struct {
	priv      ed448.PrivateKey
	pub       ed448.PublicKey
	canSign   bool
	canVerify bool
}

func (key *Ed448) Sign(payload []byte) (signature []byte, err error) {
	if !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed448.Sign(key.priv, payload)
	return
}

func (key *Ed448) Verify(payload, signature []byte) error {
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed448.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
