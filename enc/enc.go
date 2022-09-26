// package enc provides interfaces for Content Encryption.
package enc

import "io"

// Algorithm is an algorithm for encryption.
type Algorithm interface {
	Decrypt(rand io.Reader, cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error)
	Encrypt(rand io.Reader, aad, plaintext []byte) (cek, iv, ciphertext, authTag []byte, err error)
}
