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
	Decrypt(rand io.Reader, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error)
	Encrypt(rand io.Reader, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error)
}
