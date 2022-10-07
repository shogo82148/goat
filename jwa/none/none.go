// package none implements no signature algorithm.
package none

import (
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var none = &Algorithm{}

// New returns a new signature algorithm that does nothing.
//
// Deprecated: Never use none algorithm.
func New() sig.Algorithm {
	return none
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.None, New)
}

var _ sig.Algorithm = (*Algorithm)(nil)

type Algorithm struct{}

var _ sig.SigningKey = (*SigningKey)(nil)

type SigningKey struct{}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	if key != nil {
		return sig.NewInvalidKey("none", key, nil)
	}
	return &SigningKey{}
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *SigningKey) Sign(payload []byte) (signature []byte, err error) {
	return []byte{}, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *SigningKey) Verify(payload, signature []byte) error {
	if len(signature) != 0 {
		return sig.ErrSignatureMismatch
	}
	return nil
}
