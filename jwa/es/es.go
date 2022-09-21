// package es implements ECDSA algorithm.
package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/shogo82148/goat/jwa"
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
	alg:  jwa.ES256,
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

var _ sig.Key = (*Key)(nil)

type Key struct {
	hash       crypto.Hash
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey, publicKey any) sig.Key {
	key := &Key{
		hash: alg.hash,
	}
	if k, ok := privateKey.(*ecdsa.PrivateKey); ok {
		if k == nil || k.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
		}
		key.privateKey = k
	} else if privateKey != nil {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	if k, ok := publicKey.(*ecdsa.PublicKey); ok {
		if k == nil || k.Curve != alg.crv {
			return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
		}
		key.publicKey = k
	} else if publicKey != nil {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	if key.privateKey != nil && key.publicKey == nil {
		key.publicKey = &key.privateKey.PublicKey
	}
	return key
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	if key.privateKey == nil {
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
func (key *Key) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
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
