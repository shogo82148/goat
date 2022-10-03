// Package dir implements direct use of a shared symmetric key as the CEK.
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

type Options struct {
	Key []byte
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(privateKey, publicKey any) keymanage.KeyWrapper {
	key, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("dir: invalid option type: %T", privateKey))
	}
	return &KeyWrapper{
		cek: key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	cek []byte
}

func (w *KeyWrapper) WrapKey(cek []byte) (map[string]any, []byte, error) {
	return nil, []byte{}, nil
}

func (w *KeyWrapper) UnwrapKey(header map[string]any, data []byte) ([]byte, error) {
	return w.cek, nil
}
