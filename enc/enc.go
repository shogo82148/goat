// package enc provides interfaces for Content Encryption.
package enc

// Algorithm is an algorithm for encryption.
type Algorithm interface {
	// GenerateCEK generates a new CEK(Content Encryption Key).
	GenerateCEK() ([]byte, error)

	// IVSice generates a new IV(Initialization Vector).
	GenerateIV() ([]byte, error)

	// Decrypt decrypts and verifies ciphertext.
	Decrypt(cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error)

	// Encrypt encrypts and signs plaintext.
	Encrypt(cek, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error)
}
