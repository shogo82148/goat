package agcmkw

import (
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{}

func New() keymanage.Algorithm {
	return alg
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.A128GCMKW, New)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct{}

type Options struct {
	Key []byte
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("dir: invalid option type: %T", opts))
	}
	return &KeyWrapper{
		cek: key.Key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	cek []byte
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	return nil, errors.New("TODO: implement me!!")
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	return nil, errors.New("TODO: implement me!!")
}
