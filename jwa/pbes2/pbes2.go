package pbes2

import (
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{}

func NewHS256A128KW() keymanage.Algorithm {
	return alg
}

func NewHS384A192KW() keymanage.Algorithm {
	return alg
}

func NewHS512A256KW() keymanage.Algorithm {
	return alg
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS256_A128KW, NewHS256A128KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS384_A192KW, NewHS384A192KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS512_A256KW, NewHS512A256KW)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct{}

type Options struct {
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("pbes2: invalid option type: %T", opts))
	}
	_ = key
	return &KeyWrapper{}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	return nil, errors.New("pbes2: TODO implement me")
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	return nil, errors.New("pbes2: TODO implement me")
}
