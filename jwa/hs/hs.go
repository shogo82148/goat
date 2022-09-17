// package hs implements HMAC algorithm for JSON Web Signature (JWS) using SHA-2.
package hs

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var hs256 = &Algorithm{
	alg:  jwa.HS256,
	hash: sha256.New,
}

func NewHS256() sig.Algorithm {
	return hs256
}

var hs384 = &Algorithm{
	alg:  jwa.HS384,
	hash: sha512.New384,
}

func NewHS384() sig.Algorithm {
	return hs384
}

var hs512 = &Algorithm{
	alg:  jwa.HS256,
	hash: sha512.New,
}

func NewHS512() sig.Algorithm {
	return hs512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.HS256, NewHS256)
	jwa.RegisterSignatureAlgorithm(jwa.HS384, NewHS384)
	jwa.RegisterSignatureAlgorithm(jwa.HS512, NewHS512)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash func() hash.Hash
}

var _ sig.Key = (*Key)(nil)

type Key struct {
	hash func() hash.Hash
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
	mac := hmac.New(key.hash, key.key)
	if _, err := mac.Write(payload); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Verify(payload, signature []byte) error {
	mac := hmac.New(key.hash, key.key)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum(nil)
	if !hmac.Equal(signature, sum) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
