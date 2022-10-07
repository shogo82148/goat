// package es implements a signing algorithm ECDSA using SHA-2.
package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

var es256 = &Algorithm{
	alg:  jwa.ES256,
	hash: crypto.SHA256,
	crv:  elliptic.P256(),
}

func New256() sig.Algorithm {
	return es256
}

var es384 = &Algorithm{
	alg:  jwa.ES384,
	hash: crypto.SHA384,
	crv:  elliptic.P384(),
}

func New384() sig.Algorithm {
	return es384
}

var es512 = &Algorithm{
	alg:  jwa.ES512,
	hash: crypto.SHA512,
	crv:  elliptic.P521(),
}

func New512() sig.Algorithm {
	return es512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.ES256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.ES384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.ES512, New512)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	crv  elliptic.Curve
}

var _ sig.SigningKey = (*SigningKey)(nil)

type SigningKey struct {
	hash       crypto.Hash
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	canSign    bool
	canVerify  bool
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()
	k := &SigningKey{
		hash:      alg.hash,
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}
	if key, ok := priv.(*ecdsa.PrivateKey); ok {
		if key == nil || key.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
		k.privateKey = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if key, ok := pub.(*ecdsa.PublicKey); ok {
		if key != nil && key.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
		k.publicKey = key
	} else if pub != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if k.privateKey != nil && k.publicKey == nil {
		k.publicKey = &k.privateKey.PublicKey
	}
	return k
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *SigningKey) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	if key.privateKey == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}

	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key.privateKey, sum)
	if err != nil {
		return nil, err
	}
	bits := key.privateKey.Curve.Params().BitSize
	size := (bits + 7) / 8

	ret := make([]byte, 2*size)
	r.FillBytes(ret[:size])
	s.FillBytes(ret[size:])
	return ret, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *SigningKey) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
	}
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}

	bits := key.publicKey.Curve.Params().BitSize
	size := (bits + 7) / 8
	if len(signature) != 2*size {
		return sig.ErrSignatureMismatch
	}

	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return err
	}
	sum := hash.Sum(nil)

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(key.publicKey, sum, r, s) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
