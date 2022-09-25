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

var _ enc.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	encKeyLen int
	macKeyLen int
	hash      crypto.Hash
	tLen      int
}

func (alg *Algorithm) NewCEK(cek []byte) enc.Key {
	if len(cek) != alg.encKeyLen+alg.macKeyLen {
		return nil
	}
	return &Key{
		enc: cek[alg.macKeyLen:],
		mac: cek[:alg.macKeyLen],
		alg: alg,
	}
}

var _ enc.Key = (*Key)(nil)

type Key struct {
	// key for AES
	enc []byte

	// key for HMAC
	mac []byte

	alg *Algorithm
}

func (key *Key) Decrypt(rand io.Reader, iv, aad, ciphertext, authTag []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key.enc)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	size := block.BlockSize()
	plaintext = make([]byte, len(ciphertext))
	mac := hmac.New(key.alg.hash.New, key.mac)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(aad))*8)
	mac.Write(buf[:])
	expectedAuthTag := mac.Sum(nil)[:key.alg.tLen]

	for i := 0; i <= len(ciphertext)-size; i += size {
		mode.CryptBlocks(plaintext[i:i+size], ciphertext[i:i+size])
	}
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]

	if !hmac.Equal(authTag, expectedAuthTag) {
		return nil, errors.New("acbc: authentication tag mismatch")
	}
	return
}
func (key *Key) Encrypt(rand io.Reader, iv, aad, plaintext []byte) (ciphertext, authTag []byte, err error) {
	return
}
