// Package dir provides the direct key wrapping algorithm.
package dir

import (
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
func (alg *Algorithm) NewKeyWrapper(key keymanage.Key) keymanage.KeyWrapper {
	privateKey := key.PrivateKey()
	cek, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("dir: invalid key type: %T", privateKey))
	}
	return &KeyWrapper{
		cek: cek,
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

func (w *KeyWrapper) DeriveKey(opts any) (cek, encryptedCEK []byte, err error) {
	return []byte{}, w.cek, nil
}
