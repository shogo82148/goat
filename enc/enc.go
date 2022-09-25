// package enc provides interfaces for Content Encryption.
package enc

import "io"

// Algorithm is an algorithm for encryption.
type Algorithm interface {
	// NewCEK returns a new CEK (Content Encryption Key).
	NewCEK(cek []byte) Key
}

// Key is a content encryption key.
type Key interface {
	Decrypt(rand io.Reader, ciphertext []byte) (plaintext []byte, err error)
	Encrypt(rand io.Reader, plaintext []byte) (ciphertext []byte, err error)
}
