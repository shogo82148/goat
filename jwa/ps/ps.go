// Package ps implements RSASSA-PSS Digital Signature.
package ps

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var ps256 = &Algorithm{
	alg:  jwa.PS256,
	hash: crypto.SHA256,
}

func New256() sig.Algorithm {
	return ps256
}

var ps384 = &Algorithm{
	alg:  jwa.PS384,
	hash: crypto.SHA384,
}

func New384() sig.Algorithm {
	return ps384
}

var ps512 = &Algorithm{
	alg:  jwa.PS512,
	hash: crypto.SHA512,
}

func New512() sig.Algorithm {
	return ps512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.PS256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.PS384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.PS512, New512)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	weak bool
}

var _ sig.Key = (*Key)(nil)

type Key struct {
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey, publicKey any) sig.Key {
	key := &Key{
		hash: alg.hash,
	}
	if k, ok := privateKey.(*rsa.PrivateKey); ok {
		key.privateKey = k
	} else if privateKey != nil {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	if k, ok := publicKey.(*rsa.PublicKey); ok {
		key.publicKey = k
	} else if publicKey != nil {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	if key.privateKey != nil && key.publicKey == nil {
		key.publicKey = &key.privateKey.PublicKey
	}
	if key.publicKey == nil {
		return sig.NewInvalidKey(alg.alg.String(), privateKey, publicKey)
	}
	if !alg.weak {
		if size := key.publicKey.N.BitLen(); size < 2048 {
			return sig.NewErrorKey(fmt.Errorf("ps: weak key bit length: %d", size))
		}
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
	return rsa.SignPSS(rand.Reader, key.privateKey, key.hash, hash.Sum(nil), nil)
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
	}
	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return err
	}
	return rsa.VerifyPSS(key.publicKey, key.hash, hash.Sum(nil), signature, nil)
}
