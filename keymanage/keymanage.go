// Package keymanage defines the interface of Key Management Algorithms.
package keymanage

type Algorithm interface {
	NewKeyWrapper(privateKey, publicKey any) KeyWrapper
}

type KeyWrapper interface {
	WrapKey(cek []byte, opts any) (data []byte, err error)
	UnwrapKey(data []byte, opts any) (cek []byte, err error)
}

func NewInvalidKeyWrapper(err error) KeyWrapper {
	return &invalidKeyWrapper{
		err: err,
	}
}

type invalidKeyWrapper struct {
	err error
}

func (w *invalidKeyWrapper) WrapKey(cek []byte, opts any) (data []byte, err error) {
	return nil, w.err
}

func (w *invalidKeyWrapper) UnwrapKey(data []byte, opts any) (cek []byte, err error) {
	return nil, w.err
}
