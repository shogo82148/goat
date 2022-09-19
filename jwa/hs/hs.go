// package hs implements HMAC algorithm for JSON Web Signature (JWS) using SHA-2.
package hs

import (
	"crypto"
	"crypto/hmac"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var hs256 = &Algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA256,
}

func New256() sig.Algorithm {
	return hs256
}

var hs384 = &Algorithm{
	alg:  jwa.HS384,
	hash: crypto.SHA384,
}

func New384() sig.Algorithm {
	return hs384
}

var hs512 = &Algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA512,
}

func New512() sig.Algorithm {
	return hs512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.HS256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.HS384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.HS512, New512)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

var _ sig.Key = (*Key)(nil)

type Key struct {
	hash crypto.Hash
	key  []byte
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey, publicKey any) sig.Key {
	key, ok := privateKey.([]byte)
	if !ok {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	return &Key{
		hash: alg.hash,
		key:  key,
	}
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	mac := hmac.New(key.hash.New, key.key)
	if _, err := mac.Write(payload); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Verify(payload, signature []byte) error {
	mac := hmac.New(key.hash.New, key.key)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum(nil)
	if !hmac.Equal(signature, sum) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
