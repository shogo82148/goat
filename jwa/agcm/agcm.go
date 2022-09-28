// Package agcm implements key wrapping with AES GCM.
package agcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/shogo82148/goat/enc"
	"github.com/shogo82148/goat/jwa"
)

const nonceSize = 12

var a128gcm = &Algorithm{
	keyLen: 16,
}

func New128() enc.Algorithm {
	return a128gcm
}

var a192gcm = &Algorithm{
	keyLen: 24,
}

func New192() enc.Algorithm {
	return a192gcm
}

var a256gcm = &Algorithm{
	keyLen: 32,
}

func New256() enc.Algorithm {
	return a256gcm
}

func init() {
	jwa.RegisterEncryptionAlgorithm(jwa.A128GCM, New128)
	jwa.RegisterEncryptionAlgorithm(jwa.A192GCM, New192)
	jwa.RegisterEncryptionAlgorithm(jwa.A256GCM, New256)
}

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keyLen int
}

func (alg *Algorithm) CEKSize() int {
	return alg.keyLen
}

func (alg *Algorithm) IVSize() int {
	return nonceSize
}

func (alg *Algorithm) Decrypt(cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error) {
	// decrypt
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// copy ciphertext and authTag to pre-allocated buffer
	buf := make([]byte, len(ciphertext)+len(authTag))
	copy(buf, ciphertext)
	copy(buf[len(ciphertext):], authTag)
	return aead.Open(buf[:0], iv, buf, aad)
}

func (alg *Algorithm) Encrypt(cek, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error) {
	// verify parameters
	if len(cek) != alg.keyLen {
		return nil, nil, fmt.Errorf("agcm: the size of CEK must be %d bytes, but got: %d", alg.keyLen, len(cek))
	}
	if len(iv) != nonceSize {
		return nil, nil, fmt.Errorf("agcm: the size of IV must be %d bytes, but got: %d", nonceSize, len(iv))
	}

	// encrypt
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, iv, plaintext, aad)
	ciphertext, authTag = ciphertext[:len(plaintext)], ciphertext[len(plaintext):]
	return
}
