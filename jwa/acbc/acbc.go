// package acbc provides AES_CBC_HMAC_SHA2 Algorithms.
package acbc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"

	"github.com/shogo82148/goat/enc"
)

var a128cbc_hs256 = &Algorithm{
	encKeyLen: 16,
	macKeyLen: 16,
	hash:      crypto.SHA256,
	tLen:      16,
}

func New128CBC_HS256() enc.Algorithm {
	return a128cbc_hs256
}

func init() {
}

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	encKeyLen int
	macKeyLen int
	hash      crypto.Hash
	tLen      int
}

func (alg *Algorithm) Decrypt(rand io.Reader, cek, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error) {
	if len(cek) != alg.macKeyLen+alg.encKeyLen {
		return nil, errors.New("acbc: invalid content encryption key")
	}
	mac := cek[:alg.macKeyLen]
	enc := cek[alg.macKeyLen:]

	// check the authentication tag
	plaintext = make([]byte, len(ciphertext))
	expectedAuthTag := alg.calcAuthTag(mac, aad, iv, ciphertext)
	if !hmac.Equal(authTag, expectedAuthTag) {
		return nil, errors.New("acbc: authentication tag mismatch")
	}

	// decrypt
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	size := block.BlockSize()
	for i := 0; i <= len(ciphertext)-size; i += size {
		mode.CryptBlocks(plaintext[i:i+size], ciphertext[i:i+size])
	}
	pad := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-pad]

	return
}

func (alg *Algorithm) Encrypt(rand io.Reader, aad, plaintext []byte) (cek, iv, ciphertext, authTag []byte, err error) {
	cek = make([]byte, alg.encKeyLen+alg.macKeyLen)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, nil, nil, err
	}
	mac := cek[:alg.macKeyLen]
	enc := cek[alg.macKeyLen:]
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	size := block.BlockSize()

	// padding
	l := len(plaintext)
	pad := size - (l % size)
	l += pad

	// encrypt
	iv = make([]byte, size)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, nil, nil, err
	}
	ciphertext = make([]byte, l)
	copy(ciphertext, plaintext)
	for i := len(plaintext); i < l; i++ {
		ciphertext[i] = byte(pad)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	for i := 0; i <= len(ciphertext)-size; i += size {
		mode.CryptBlocks(ciphertext[i:i+size], ciphertext[i:i+size])
	}
	authTag = alg.calcAuthTag(mac, aad, iv, ciphertext)

	return
}

func (alg *Algorithm) calcAuthTag(mac, aad, iv, ciphertext []byte) []byte {
	w := hmac.New(alg.hash.New, mac)
	w.Write(aad)
	w.Write(iv)
	w.Write(ciphertext)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(aad))*8)
	w.Write(buf[:])
	return w.Sum(nil)[:alg.tLen]
}