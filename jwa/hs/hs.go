// Package hs provides the HMAC using SHA-2 signature algorithm.
package hs

import (
	"crypto"
	"crypto/hmac"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/sig"
)

var hs256 = &algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA256,
}

// New256 returns HS256 (HMAC using SHA-256) signature algorithm.
//
// New256 doesn't accept weak keys less than 256 bit.
// If you want to use weak keys, use New256Weak instead.
func New256() sig.Algorithm {
	return hs256
}

var hs384 = &algorithm{
	alg:  jwa.HS384,
	hash: crypto.SHA384,
}

// New384 returns HS384 (HMAC using SHA-384) signature algorithm.
//
// New384 doesn't accept weak keys less than 384 bit.
// If you want to use weak keys, use New384Weak instead.
func New384() sig.Algorithm {
	return hs384
}

var hs512 = &algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA512,
}

// New512 returns HS512 (HMAC using SHA-512) signature algorithm.
//
// New512 doesn't accept weak keys less than 512 bit.
// If you want to use weak keys, use New512Weak instead.
func New512() sig.Algorithm {
	return hs512
}

var hs256w = &algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA256,
	weak: true,
}

// New256Weak is same as New256, but it accepts the weak keys.
//
// Deprecated: Use New256 instead.
func New256Weak() sig.Algorithm {
	return hs256w
}

var hs384w = &algorithm{
	alg:  jwa.HS384,
	hash: crypto.SHA384,
	weak: true,
}

// New384Weak is same as New384, but it accepts the weak keys.
//
// Deprecated: Use New384 instead.
func New384Weak() sig.Algorithm {
	return hs384w
}

var hs512w = &algorithm{
	alg:  jwa.HS256,
	hash: crypto.SHA512,
	weak: true,
}

// New512Weak is same as New512, but it accepts the weak keys.
//
// Deprecated: Use New512 instead.
func New512Weak() sig.Algorithm {
	return hs512w
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.HS256, New256)
	jwa.RegisterSignatureAlgorithm(jwa.HS384, New384)
	jwa.RegisterSignatureAlgorithm(jwa.HS512, New512)
}

var _ sig.Algorithm = (*algorithm)(nil)

// algorithm is HMAC using SHA-2.
//
// By default, using weak keys that have the smaller size than the hash output fails.
// If you want to use weak keys, use New256Weak, New384Weak, and New512Weak instead of
// New256, New384, and New512.
type algorithm struct {
	alg  jwa.SignatureAlgorithm
	hash crypto.Hash
	weak bool
}

var _ sig.SigningKey = (*signingKey)(nil)

// signingKey is a key for signing.
type signingKey struct {
	hash      crypto.Hash
	key       []byte
	canSign   bool
	canVerify bool
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()

	secret, ok := priv.([]byte)
	if !ok || key == nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if pub != nil {
		return sig.NewInvalidKey(alg.alg.String(), priv, pub)
	}
	if !alg.weak {
		if len(secret) < alg.hash.Size() {
			return sig.NewErrorKey(fmt.Errorf("hs: weak key size: %d", len(secret)))
		}
	}
	return &signingKey{
		hash:      alg.hash,
		key:       secret,
		canSign:   jwktypes.CanUseFor(key, jwktypes.KeyOpSign),
		canVerify: jwktypes.CanUseFor(key, jwktypes.KeyOpVerify),
	}
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	if !key.hash.Available() {
		return nil, sig.ErrHashUnavailable
	}
	if !key.canSign {
		return nil, sig.ErrSignUnavailable
	}
	mac := hmac.New(key.hash.New, key.key)
	if _, err := mac.Write(payload); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Verify(payload, signature []byte) error {
	mac := hmac.New(key.hash.New, key.key)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	if !key.canVerify {
		return sig.ErrSignUnavailable
	}
	sum := mac.Sum(nil)
	if !hmac.Equal(signature, sum) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
