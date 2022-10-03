package pbes2

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwa/akw"
	"github.com/shogo82148/goat/keymanage"
	"golang.org/x/crypto/pbkdf2"
)

var a128kw = &Algorithm{
	name: string(jwa.PBES2_HS256_A128KW),
	hash: crypto.SHA256.New,
	alg:  akw.New128,
	size: 16,
}

func NewHS256A128KW() keymanage.Algorithm {
	return a128kw
}

var a192kw = &Algorithm{
	name: string(jwa.PBES2_HS384_A192KW),
	hash: crypto.SHA384.New,
	alg:  akw.New192,
	size: 24,
}

func NewHS384A192KW() keymanage.Algorithm {
	return a192kw
}

var a256kw = &Algorithm{
	name: string(jwa.PBES2_HS512_A256KW),
	hash: crypto.SHA512.New,
	alg:  akw.New256,
	size: 32,
}

func NewHS512A256KW() keymanage.Algorithm {
	return a256kw
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS256_A128KW, NewHS256A128KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS384_A192KW, NewHS384A192KW)
	jwa.RegisterKeyManagementAlgorithm(jwa.PBES2_HS512_A256KW, NewHS512A256KW)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	name string
	hash func() hash.Hash
	alg  func() keymanage.Algorithm
	size int
}

type Options struct {
	PrivateKey []byte

	// PBES2SaltInput is RFC7518 Section 4.8.1.1. "p2s" (PBES2 Salt Input) Header Parameter.
	PBES2SaltInput []byte

	// PBES2Count is RFC7518 Section 4.8.1.2. "p2c" (PBES2 Count) Header Parameter.
	PBES2Count int
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("pbes2: invalid option type: %T", opts))
	}
	salt := make([]byte, 0, len(alg.name)+len(key.PBES2SaltInput))
	salt = append(salt, []byte(alg.name)...)
	salt = append(salt, '\x00')
	salt = append(salt, key.PBES2SaltInput...)
	dk := pbkdf2.Key(key.PrivateKey, salt, key.PBES2Count, alg.size, alg.hash)
	return &KeyWrapper{
		alg: alg.alg,
		key: dk,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	alg func() keymanage.Algorithm
	key []byte
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	kw := w.alg().NewKeyWrapper(&akw.Options{
		Key: w.key,
	})
	data, err := kw.WrapKey(cek)
	if err != nil {
		return nil, fmt.Errorf("pbse2: failed to wrap key: %w", err)
	}
	return data, nil
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	kw := w.alg().NewKeyWrapper(&akw.Options{
		Key: w.key,
	})
	cek, err := kw.UnwrapKey(data)
	if err != nil {
		return nil, fmt.Errorf("pbse2: failed to unwrap key: %w", err)
	}
	return cek, nil
}
