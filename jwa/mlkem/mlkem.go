package mlkem

import (
	"errors"

	"github.com/shogo82148/goat/keymanage"
)

var mlkem768 = &algorithm{}

func NewMLKEM768() keymanage.Algorithm {
	return mlkem768
}

var mlkem1024 = &algorithm{}

func NewMLKEM1024() keymanage.Algorithm {
	return mlkem1024
}

var _ keymanage.Algorithm = (*algorithm)(nil)

type algorithm struct{}

func (a *algorithm) NewKeyWrapper(key keymanage.Key) keymanage.KeyWrapper {
	// TODO: implement me!
	return &keyWrapper{}
}

type keyWrapper struct {
}

func (w *keyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	// TODO: implement me!
	return nil, errors.New("mlkem: not implemented")
}

func (w *keyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	// TODO: implement me!
	return nil, errors.New("mlkem: not implemented")
}

func (w *keyWrapper) DeriveKey(opts any) (cek, encryptedCEK []byte, err error) {
	// TODO: implement me!
	return nil, nil, errors.New("mlkem: not implemented")
}
