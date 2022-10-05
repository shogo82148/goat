// package none implements no signature algorithm.
package none

import (
	"crypto"

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

var _ sig.Key = (*Key)(nil)

type Key struct{}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) sig.Key {
	if privateKey != nil || publicKey != nil {
		return sig.NewInvalidKey("none", privateKey, publicKey)
	}
	return &Key{}
}

// Sign implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Sign(payload []byte) (signature []byte, err error) {
	return []byte{}, nil
}

// Verify implements [github.com/shogo82148/goat/sig.Key].
func (key *Key) Verify(payload, signature []byte) error {
	if len(signature) != 0 {
		return sig.ErrSignatureMismatch
	}
	return nil
}
