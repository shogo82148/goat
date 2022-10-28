// Package agcm provides the AES-GCM content encryption algorithm.
package agcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/enc"
	"github.com/shogo82148/goat/jwa"
)

const nonceSize = 12

func New128() enc.Algorithm {
	return &Algorithm{
		keyLen: 16,
	}
}

func New192() enc.Algorithm {
	return &Algorithm{
		keyLen: 24,
	}
}

func New256() enc.Algorithm {
	return &Algorithm{
		keyLen: 32,
	}
}

func init() {
	jwa.RegisterEncryptionAlgorithm(jwa.A128GCM, New128)
	jwa.RegisterEncryptionAlgorithm(jwa.A192GCM, New192)
	jwa.RegisterEncryptionAlgorithm(jwa.A256GCM, New256)
}

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keyLen int

	mask    [nonceSize]byte
	counter uint64
}

func (alg *Algorithm) GenerateCEK() ([]byte, error) {
	cek := make([]byte, alg.keyLen)
	_, err := rand.Read(cek)
	if err != nil {
		return nil, err
	}
	alg.counter = 0
	return cek, nil
}

func (alg *Algorithm) GenerateIV() ([]byte, error) {
	c := alg.counter
	if c == 0 {
		_, err := rand.Read(alg.mask[:])
		if err != nil {
			return nil, err
		}
	}
	c++
	if c == 0 {
		return nil, errors.New("agcm: counter overflow")
	}

	alg.counter = c
	var iv [nonceSize]byte
	copy(iv[:], alg.mask[:])
	iv[nonceSize-1] ^= byte(c)
	iv[nonceSize-2] ^= byte(c >> 8)
	iv[nonceSize-3] ^= byte(c >> 16)
	iv[nonceSize-4] ^= byte(c >> 24)
	iv[nonceSize-5] ^= byte(c >> 32)
	iv[nonceSize-6] ^= byte(c >> 40)
	iv[nonceSize-7] ^= byte(c >> 48)
	iv[nonceSize-8] ^= byte(c >> 56)
	return iv[:], nil
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
