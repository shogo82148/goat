// Package rs provides the RSASSA-PKCS1-v1_5 using SHA-2 signature algorithm.
package rs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

var rs256 = &algorithm{
	alg:  jwa.RS256,
	hash: crypto.SHA256,
}

// New256 returns RS256 signature algorithm.
//
// New256 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New256Weak instead.
func New256() sig.Algorithm {
	return rs256
}

var rs384 = &algorithm{
	alg:  jwa.RS384,
	hash: crypto.SHA384,
}

// New384 returns RS384 signature algorithm.
//
// New384 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New384Weak instead.
func New384() sig.Algorithm {
	return rs384
}

var rs512 = &algorithm{
	alg:  jwa.RS512,
	hash: crypto.SHA512,
}

// New512 returns RS512 signature algorithm.
//
// New512 doesn't accept weak keys less than 2048 bit.
// If you want to use weak keys, use New512Weak instead.
func New512() sig.Algorithm {
	return rs512
}

var rs256w = &algorithm{
	alg:  jwa.RS256,
	hash: crypto.SHA256,
	weak: true,
}

// New256Weak is same as New256, but it accepts the weak keys.
//
// Deprecated: Use New256 instead.
func New256Weak() sig.Algorithm {
	return rs256w
}

var rs384w = &algorithm{
	alg:  jwa.RS384,
	hash: crypto.SHA384,
	weak: true,
}

// New384Weak is same as New384, but it accepts the weak keys.
//
// Deprecated: Use New384 instead.
func New384Weak() sig.Algorithm {
	return rs384w
}

var rs512w = &algorithm{
	alg:  jwa.RS512,
	hash: crypto.SHA512,
	weak: true,
}

// New512Weak is same as New512, but it accepts the weak keys.
//
// Deprecated: Use New512 instead.
func New512Weak() sig.Algorithm {
	return rs512w
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.RS256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.RS384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.RS512, New512)
}

var _ sig.Algorithm = (*algorithm)(nil)

// algorithm is RSASSA-PKCS1-v1_5.
//
// By default, using weak keys less 2048 bits fails.
// If you want to use weak keys, use New256Weak, New384Weak, and New512Weak instead of
// New256, New384, and New512.
type algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	weak bool
}

var _ sig.SigningKey = (*signingKey)(nil)

type signingKey struct {
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	canSign    bool
	canVerify  bool
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()

	k := &signingKey{
		hash:      alg.hash,
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
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
			return sig.NewErrorKey(fmt.Errorf("rs: weak key bit length: %d", size))
		}
	}
	return k
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
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
	return rsa.SignPKCS1v15(rand.Reader, key.privateKey, key.hash, hash.Sum(nil))
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Verify(payload, signature []byte) error {
	if !key.hash.Available() {
		return sig.ErrHashUnavailable
	}
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	hash := key.hash.New()
	if _, err := hash.Write(payload); err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(key.publicKey, key.hash, hash.Sum(nil), signature)
}
