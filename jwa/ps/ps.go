// Package ps implements a signing algorithm
// RSASSA-PSS Digital Signature.
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

// New256 returns PS256 signature algorithm.
//
// New256 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New256Weak instead.
func New256() sig.Algorithm {
	return ps256
}

var ps384 = &Algorithm{
	alg:  jwa.PS384,
	hash: crypto.SHA384,
}

// New384 returns PS384 signature algorithm.
//
// New384 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New384Weak instead.
func New384() sig.Algorithm {
	return ps384
}

var ps512 = &Algorithm{
	alg:  jwa.PS512,
	hash: crypto.SHA512,
}

// New512 returns PS512 signature algorithm.
//
// New512 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New512Weak instead.
func New512() sig.Algorithm {
	return ps512
}

var ps256w = &Algorithm{
	alg:  jwa.RS256,
	hash: crypto.SHA256,
	weak: true,
}

// New256Weak is same as New256, but it accepts the weak keys.
//
// Deprecated: Use New256 instead.
func New256Weak() sig.Algorithm {
	return ps256w
}

var ps384w = &Algorithm{
	alg:  jwa.RS384,
	hash: crypto.SHA384,
	weak: true,
}

// New384Weak is same as New384, but it accepts the weak keys.
//
// Deprecated: Use New384 instead.
func New384Weak() sig.Algorithm {
	return ps384w
}

var ps512w = &Algorithm{
	alg:  jwa.RS512,
	hash: crypto.SHA512,
	weak: true,
}

// New512Weak is same as New512, but it accepts the weak keys.
//
// Deprecated: Use New512 instead.
func New512Weak() sig.Algorithm {
	return ps512w
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

var _ sig.SigningKey = (*Key)(nil)

type Key struct {
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()
	k := &Key{
		hash: alg.hash,
	}
	if key, ok := priv.(*rsa.PrivateKey); ok {
		k.privateKey = key
	} else if priv != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if key, ok := pub.(*rsa.PublicKey); ok {
		k.publicKey = key
	} else if pub != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if k.privateKey != nil && k.publicKey == nil {
		k.publicKey = &k.privateKey.PublicKey
	}
	if k.publicKey == nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if !alg.weak {
		if size := k.publicKey.N.BitLen(); size < 2048 {
			return sig.NewErrorKey(fmt.Errorf("ps: weak key bit length: %d", size))
		}
	}
	return k
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
