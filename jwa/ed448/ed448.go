// Package ed448 provides the Edwards-Curve Digital Signature Algorithm using the Ed448 parameter set defined in RFC 8032.
package ed448

import (
	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

// New returns Edwards-Curve Digital Signature Algorithm using the Ed448 parameter set.
func New() sig.Algorithm {
	return &algorithm{}
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.SignatureAlgorithmEd448, New)
}

type algorithm struct{}

func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()

	k := &signingKey{
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}
	if key, ok := priv.(ed448.PrivateKey); ok {
		k.priv = key
	} else if priv != nil {
		return sig.NewInvalidKey("ed448", priv, pub)
	}
	if key, ok := pub.(ed448.PublicKey); ok {
		k.pub = key
	} else if pub != nil {
		return sig.NewInvalidKey("ed448", priv, pub)
	}
	return k
}

type signingKey struct {
	priv      ed448.PrivateKey
	pub       ed448.PublicKey
	canSign   bool
	canVerify bool
}

func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	if key.priv == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	signature = ed448.Sign(key.priv, payload)
	return
}

func (key *signingKey) Verify(payload, signature []byte) error {
	if key.pub == nil || !key.canVerify {
		return sig.ErrSignUnavailable
	}
	if !ed448.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
