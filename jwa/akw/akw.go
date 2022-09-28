// Package akw implements AES Key Wrap key management algorithm.
package akw

import (
	"crypto/aes"
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
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keySize int
}

func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.([]byte)
	if !ok {
		return nil
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
func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	if len(cek)%chunkLen != 0 {
		return nil, fmt.Errorf("akw: invalid CEK length: %d", len(cek))
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
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
	return buf[chunkLen:], nil
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	return nil, nil
}
