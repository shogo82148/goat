// Package akw implements AES Key Wrap key management algorithm.
package akw

import (
	"crypto/aes"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var a128 = &Algorithm{
	keySize: 16,
}

func New128() keymanage.Algorithm {
	return a128
}

var a192 = &Algorithm{
	keySize: 24,
}

func New192() keymanage.Algorithm {
	return a192
}

var a256 = &Algorithm{
	keySize: 32,
}

func New256() keymanage.Algorithm {
	return a256
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.A128KW, New128)
	jwa.RegisterKeyManagementAlgorithm(jwa.A192KW, New192)
	jwa.RegisterKeyManagementAlgorithm(jwa.A256KW, New256)
}

func NewKeyWrapper(privateKey []byte) keymanage.KeyWrapper {
	switch len(privateKey) {
	case 16, 24, 32:
		return &KeyWrapper{
			key: privateKey,
		}
	}
	return keymanage.NewInvalidKeyWrapper(fmt.Errorf("akw: invalid key size: %d", len(privateKey)))
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keySize int
}

type Options struct {
	Key []byte
}

func (alg *Algorithm) NewKeyWrapper(privateKey, publicKey any) keymanage.KeyWrapper {
	key, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("akw: invalid private key type: []byte is required but got %T", privateKey))
	}
	if len(key) != alg.keySize {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("akw: invalid key size: %d is required but got %d", alg.keySize, len(key)))
	}
	return &KeyWrapper{
		key: key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	key []byte
}

// from RFC 3394 Section 2.2.3.1 Default Initial Value
var defaultIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

const chunkLen = 8

// WrapKey wraps cek with AWS Key Wrap algorithm
// defined in [RFC 3394].
//
// [RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
func (w *KeyWrapper) WrapKey(cek []byte) (map[string]any, []byte, error) {
	if len(cek)%chunkLen != 0 {
		return nil, nil, fmt.Errorf("akw: invalid CEK length: %d", len(cek))
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, nil, err
	}

	n := len(cek) / chunkLen
	buf := make([]byte, len(cek)+chunkLen*2)
	r := buf[chunkLen*2:]
	copy(r, cek)

	a := buf[:chunkLen]
	b := buf[chunkLen : chunkLen*2]
	ab := buf[:chunkLen*2]
	copy(a, defaultIV)
	for t := 0; t < 6*n; t++ {
		// A[t-1] | R[t-1][1]
		copy(b, r[(t%n)*chunkLen:])

		// AES(K, A[t-1] | R[t-1][1])
		block.Encrypt(ab, ab)

		// MSB(64, AES(K, A[t-1] | R[t-1][1])) ^ t
		u := t + 1
		a[0] ^= byte(u >> 56)
		a[1] ^= byte(u >> 48)
		a[2] ^= byte(u >> 40)
		a[3] ^= byte(u >> 32)
		a[4] ^= byte(u >> 24)
		a[5] ^= byte(u >> 16)
		a[6] ^= byte(u >> 8)
		a[7] ^= byte(u)

		// R[t][n] = LSB(64, AES(K, A[t-1] | R[t-1][1]))
		copy(r[(t%n)*chunkLen:], b)
	}

	copy(b, a)
	return nil, buf[chunkLen:], nil
}

// UnwrapKey unwraps cek with AWS Key Wrap algorithm
// defined in [RFC 3394].
//
// [RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394
func (w *KeyWrapper) UnwrapKey(header map[string]any, data []byte) ([]byte, error) {
	if len(data)%chunkLen != 0 {
		return nil, fmt.Errorf("akw: invalid CEK length: %d", len(data))
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}

	n := (len(data) / chunkLen) - 1
	buf := make([]byte, len(data)+chunkLen)
	r := buf[chunkLen*2:]
	copy(r, data[chunkLen:])

	a := buf[:chunkLen]
	b := buf[chunkLen : chunkLen*2]
	ab := buf[:chunkLen*2]
	copy(a, data)
	for t := 0; t < 6*n; t++ {
		// A[t] ^ t
		u := 6*n - t
		a[0] ^= byte(u >> 56)
		a[1] ^= byte(u >> 48)
		a[2] ^= byte(u >> 40)
		a[3] ^= byte(u >> 32)
		a[4] ^= byte(u >> 24)
		a[5] ^= byte(u >> 16)
		a[6] ^= byte(u >> 8)
		a[7] ^= byte(u)

		// A[t] ^ t) | R[t][n]
		copy(b, r[((u-1)%n)*chunkLen:])

		// A[t-1] = MSB(64, AES-1(K, ((A[t] ^ t) | R[t][n]))
		block.Decrypt(ab, ab)

		// R[t-1][1] = LSB(64, AES-1(K, ((A[t]^t) | R[t][n]))
		copy(r[((u-1)%n)*chunkLen:], b)
	}

	if subtle.ConstantTimeCompare(a, defaultIV) == 0 {
		return nil, errors.New("akw: failed to unwrap key")
	}

	return buf[chunkLen*2:], nil
}
