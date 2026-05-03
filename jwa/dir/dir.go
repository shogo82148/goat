// Package dir provides the direct key wrapping algorithm.
package dir

import (
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &algorithm{}

func New() keymanage.Algorithm {
	return alg
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.KeyManagementAlgorithmDirect, New)
}

var _ keymanage.Algorithm = (*algorithm)(nil)

type algorithm struct{}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
func (alg *algorithm) NewKeyWrapper(key keymanage.Key) keymanage.KeyWrapper {
	privateKey := key.PrivateKey()
	cek, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("dir: invalid key type: %T", privateKey))
	}
	return &keyWrapper{
		cek: cek,
	}
}

var _ keymanage.KeyWrapper = (*keyWrapper)(nil)

type keyWrapper struct {
	cek []byte
}

func (w *keyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	return []byte{}, nil
}

func (w *keyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	return w.cek, nil
}

func (w *keyWrapper) DeriveKey(opts any) (cek, encryptedCEK []byte, err error) {
	return []byte{}, w.cek, nil
}
