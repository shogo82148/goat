// Package dir implements a Key Wrapping algorithm
// that is direct use of a shared symmetric key as the CEK.
package dir

import (
	"crypto"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{}

func New() keymanage.Algorithm {
	return alg
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.Direct, New)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct{}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
func (alg *Algorithm) NewKeyWrapper(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) keymanage.KeyWrapper {
	key, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("dir: invalid key type: %T", privateKey))
	}
	return &KeyWrapper{
		cek: key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	cek []byte
}

func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	return []byte{}, nil
}

func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	return w.cek, nil
}
