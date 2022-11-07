// Package eddsa provides the Elliptic Curve Diffie-Hellman key agreement algorithm defined in RFC 8032.
package eddsa

import (
	"crypto/ed25519"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

// New returns Edwards-Curve Digital Signature Algorithm.
func New() sig.Algorithm {
	return &algorithm{}
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.EdDSA, New)
}

type algorithm struct{}

func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
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
		return &ed25519Key{
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
		return &ed448Key{
			priv:      priv,
			pub:       pubkey,
			canSign:   canSign,
			canVerify: canVerify,
		}
	case nil:
		switch pub := pub.(type) {
		case ed25519.PublicKey:
			return &ed25519Key{
				pub:       pub,
				canSign:   canSign,
				canVerify: canVerify,
			}
		case ed448.PublicKey:
			return &ed448Key{
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

type ed25519Key struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	canSign   bool
	canVerify bool
}

func (key *ed25519Key) Sign(payload []byte) (signature []byte, err error) {
	if !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed25519.Sign(key.priv, payload)
	return
}

func (key *ed25519Key) Verify(payload, signature []byte) error {
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed25519.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}

type ed448Key struct {
	priv      ed448.PrivateKey
	pub       ed448.PublicKey
	canSign   bool
	canVerify bool
}

func (key *ed448Key) Sign(payload []byte) (signature []byte, err error) {
	if !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed448.Sign(key.priv, payload)
	return
}

func (key *ed448Key) Verify(payload, signature []byte) error {
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed448.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
