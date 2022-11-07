// Package none provides none signature algorithm.
package none

import (
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var none = &algorithm{}

// New returns a new signature algorithm that does nothing.
//
// Deprecated: Never use none algorithm.
func New() sig.Algorithm {
	return none
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.None, New)
}

var _ sig.Algorithm = (*algorithm)(nil)

type algorithm struct{}

var _ sig.SigningKey = (*signingKey)(nil)

type signingKey struct{}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	if key != nil {
		return sig.NewInvalidKey("none", key, nil)
	}
	return &signingKey{}
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Sign(payload []byte) (signature []byte, err error) {
	return []byte{}, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *signingKey) Verify(payload, signature []byte) error {
	if len(signature) != 0 {
		return sig.ErrSignatureMismatch
	}
	return nil
}
