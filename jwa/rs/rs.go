package rs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var rs256 = &Algorithm{
	alg:  jwa.RS256,
	hash: crypto.SHA256,
}

func New256() sig.Algorithm {
	return rs256
}

var rs384 = &Algorithm{
	alg:  jwa.RS384,
	hash: crypto.SHA384,
}

func New384() sig.Algorithm {
	return rs384
}

var rs512 = &Algorithm{
	alg:  jwa.RS256,
	hash: crypto.SHA512,
}

func New512() sig.Algorithm {
	return rs512
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.RS256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.RS384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.RS512, New512)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
}

var _ sig.Key = (*Key)(nil)

type Key struct {
	alg        *Algorithm
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (alg *Algorithm) String() string {
	return alg.alg.String()
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey, publicKey any) sig.Key {
	key := &Key{
		hash: alg.hash,
	}
	if k, ok := privateKey.(*rsa.PrivateKey); ok {
		key.privateKey = k
	} else if privateKey != nil {
		return sig.NewInvalidKey(alg, privateKey, publicKey)
	}
	if k, ok := publicKey.(*rsa.PublicKey); ok {
		key.publicKey = k
	} else if publicKey != nil {
		return sig.NewInvalidKey(alg, privateKey, publicKey)
	}
	if key.privateKey != nil && key.publicKey == nil {
		key.publicKey = &key.privateKey.PublicKey
	}
	return key
}

func (key *Key) Algorithm() sig.Algorithm {
	return key.alg
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, key.privateKey, key.hash, hash.Sum(nil))
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
	return rsa.VerifyPKCS1v15(key.publicKey, key.hash, hash.Sum(nil), signature)
}
