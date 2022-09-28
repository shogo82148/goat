// Package agcm implements key wrapping with AES GCM.
package agcm

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/shogo82148/goat/enc"
	"github.com/shogo82148/goat/jwa"
)

var a128gcm = &Algorithm{
	keyLen: 16,
}

func New128() enc.Algorithm {
	return a128gcm
}

var a256gcm = &Algorithm{
	keyLen: 32,
}

func New256() enc.Algorithm {
	return a256gcm
}

func init() {
	jwa.RegisterEncryptionAlgorithm(jwa.A128GCM, New128)
	jwa.RegisterEncryptionAlgorithm(jwa.A256GCM, New256)
}

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keyLen int
}

func (alg *Algorithm) Decrypt(rand io.Reader, cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error) {
	// decrypt
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext = ciphertext[:len(ciphertext):len(ciphertext)]
	ciphertext = append(ciphertext, authTag...)
	return aead.Open(nil, iv, ciphertext, aad)
}

func (alg *Algorithm) Encrypt(rand io.Reader, aad, plaintext []byte) (cek, iv, ciphertext, authTag []byte, err error) {
	err = errors.New("agcm: TODO: implement")
	return
}
