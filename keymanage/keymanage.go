// Package keymanage defines the interface of Key Management Algorithms.
package keymanage

import "crypto"

// Key is a key for wrapping or unwrapping Content Encryption Key (CEK).
type Key interface {
	PrivateKey() crypto.PrivateKey
	PublicKey() crypto.PublicKey
}

// Algorithm is an algorithm for wrapping or unwrapping Content Encryption Key (CEK).
type Algorithm interface {
	NewKeyWrapper(key Key) KeyWrapper
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
