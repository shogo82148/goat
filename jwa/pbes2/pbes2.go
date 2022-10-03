package pbes2

import (
	"crypto"
	"errors"
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
	enc:  akw.New128,
	size: 16,
}

func NewHS256A128KW() keymanage.Algorithm {
	return a128kw
}

var a192kw = &Algorithm{
	name: string(jwa.PBES2_HS384_A192KW),
	hash: crypto.SHA384.New,
	enc:  akw.New192,
	size: 24,
}

func NewHS384A192KW() keymanage.Algorithm {
	return a192kw
}

var a256kw = &Algorithm{
	name: string(jwa.PBES2_HS512_A256KW),
	hash: crypto.SHA512.New,
	enc:  akw.New256,
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
	enc  func() keymanage.Algorithm
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
	return &KeyWrapper{
		alg: alg,
		key: key.PrivateKey,
		p2s: key.PBES2SaltInput,
		p2c: key.PBES2Count,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	alg *Algorithm
	key []byte
	p2s []byte
	p2c int
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	return nil, errors.New("pbes2: TODO implement me")
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	salt := make([]byte, 0, len(w.p2s)+1+len(w.alg.name))
	salt = append(salt, []byte(w.alg.name)...)
	salt = append(salt, '\x00')
	salt = append(salt, w.p2s...)
	dk := pbkdf2.Key(w.key, salt, w.p2c, w.alg.size, w.alg.hash)
	kw := akw.New128().NewKeyWrapper(&akw.Options{
		Key: dk,
	})
	return kw.UnwrapKey(data)
}
