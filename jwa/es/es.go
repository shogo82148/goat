// package es provides the ECDSA using SHA-2 signature algorithm.
package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // for crypto.SHA256
	"math/big"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/secp256k1"
	"github.com/shogo82148/goat/sig"
)

var es256 = &algorithm{
	alg:  jwa.ES256,
	hash: crypto.SHA256,
	crv:  elliptic.P256(),
}

// New256 returns ECDSA using P-256 and SHA-256.
func New256() sig.Algorithm {
	return es256
}

var es256k = &algorithm{
	alg:  jwa.ES256K,
	hash: crypto.SHA256,
	crv:  secp256k1.Curve(),
}

// New256K returns ECDSA using secp256k1 and SHA-256.
func New256K() sig.Algorithm {
	return es256k
}

var es384 = &algorithm{
	alg:  jwa.ES384,
	hash: crypto.SHA384,
	crv:  elliptic.P384(),
}

// New384 returns ECDSA using P-384 and SHA-384.
func New384() sig.Algorithm {
	return es384
}

var es512 = &algorithm{
	alg:  jwa.ES512,
	hash: crypto.SHA512,
	crv:  elliptic.P521(),
}

// New512 returns ECDSA using P-521 and SHA-512.
func New512() sig.Algorithm {
	return es512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.ES256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.ES384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.ES512, New512)
	jwa.RegisterSignatureAlgorithm(jwa.ES256K, New256K)
}

var _ sig.Algorithm = (*algorithm)(nil)

type algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	crv  elliptic.Curve
}

var _ sig.SigningKey = (*signingKey)(nil)

type signingKey struct {
	hash      crypto.Hash
	priv      *ecdsa.PrivateKey
	pub       *ecdsa.PublicKey
	canSign   bool
	canVerify bool
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	k := &signingKey{
		hash:      alg.hash,
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}

	priv := key.PrivateKey()
	pub := key.PublicKey()
	if key, ok := priv.(*ecdsa.PrivateKey); ok {
		k.priv = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if key, ok := pub.(*ecdsa.PublicKey); ok {
		k.pub = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}

	if k.priv != nil {
		if k.priv.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
	}
	if k.pub != nil {
		if k.pub.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), priv, pub)
		}
	}
	if k.priv != nil && k.pub == nil {
		k.pub = &k.priv.PublicKey
	}
	return k
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	if key.priv == nil || !key.canSign {
		return nil, sig.ErrSignUnavailable
	}

	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key.priv, sum)
	if err != nil {
		return nil, err
	}
	bits := key.priv.Curve.Params().BitSize
	size := (bits + 7) / 8

	ret := make([]byte, 2*size)
	r.FillBytes(ret[:size])
	s.FillBytes(ret[size:])
	return ret, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
	}
	if key.pub == nil || !key.canVerify {
		return sig.ErrSignUnavailable
	}

	bits := key.pub.Curve.Params().BitSize
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
	if !ecdsa.Verify(key.pub, sum, r, s) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
