// package hs implements no signature algorithm.
package hs

import (
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

var none = &Algorithm{}

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

func (alg *Algorithm) String() string {
	return jwa.None.String()
}

// NewKey implements [github.com/shogo82148/goat/sig.Algorithm].
func (alg *Algorithm) NewKey(privateKey, publicKey any) sig.Key {
	if privateKey != nil || publicKey != nil {
		return sig.NewInvalidKey(none, privateKey, publicKey)
	}
	return &Key{}
}

func (key *Key) Algorithm() sig.Algorithm {
	return none
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
