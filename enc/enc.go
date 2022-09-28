// package enc provides interfaces for Content Encryption.
package enc

// Algorithm is an algorithm for encryption.
type Algorithm interface {
	// CEKSize returns the byte size of CEK(Content Encryption Key) for the algorithm.
	CEKSize() int

	// IVSice returns the byte size of IV(Initialization Vector) for the algorithm.
	IVSize() int

	// Decrypt decrypts and verifies ciphertext.
	Decrypt(cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error)

	// Encrypt encrypts and signs plaintext.
	Encrypt(cek, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error)
}
