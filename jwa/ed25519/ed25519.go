// Package ed25519 provides the Edwards-Curve Digital Signature Algorithm using the Ed25519 parameter set defined in RFC 8032.
package ed25519

import (
	"crypto/ed25519"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

// New returns Edwards-Curve Digital Signature Algorithm using the Ed25519 parameter set.
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

	k := &signingKey{
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}
	if key, ok := priv.(ed25519.PrivateKey); ok {
		k.priv = key
	} else if priv != nil {
		return sig.NewInvalidKey("ed25519", priv, pub)
	}
	if key, ok := pub.(ed25519.PublicKey); ok {
		k.pub = key
	} else if pub != nil {
		return sig.NewInvalidKey("ed25519", priv, pub)
	}
	return k
}

type signingKey struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	canSign   bool
	canVerify bool
}

func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	if key.priv == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed25519.Sign(key.priv, payload)
	return
}

func (key *signingKey) Verify(payload, signature []byte) error {
	if key.pub == nil || !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed25519.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
