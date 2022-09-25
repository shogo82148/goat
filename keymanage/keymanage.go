// Package keymanage defines the interface of Key Management Algorithms.
package keymanage

type Algorithm interface {
	NewKeyWrapper(opts any) KeyWrapper
}

type KeyWrapper interface {
	WrapKey(cek []byte) (data []byte, err error)
	UnwrapKey(data []byte) (cek []byte, err error)
}
