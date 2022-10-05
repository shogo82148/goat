package pbes2

import (
	"crypto"
	"crypto/rand"
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
	size: 16,
}

func NewHS256A128KW() keymanage.Algorithm {
	return a128kw
}

var a192kw = &Algorithm{
	name: string(jwa.PBES2_HS384_A192KW),
	hash: crypto.SHA384.New,
	size: 24,
}

func NewHS384A192KW() keymanage.Algorithm {
	return a192kw
}

var a256kw = &Algorithm{
	name: string(jwa.PBES2_HS512_A256KW),
	hash: crypto.SHA512.New,
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
	size int
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
func (alg *Algorithm) NewKeyWrapper(privateKey, publicKey any) keymanage.KeyWrapper {
	key, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("pbes2: invalid option type: %T", privateKey))
	}
	return &KeyWrapper{
		alg: alg,
		key: key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	alg *Algorithm
	key []byte
}

type pbes2SaltInputGetter interface {
	PBES2SaltInput() []byte
}

type pbes2SaltInputSetter interface {
	SetPBES2SaltInput(p2s []byte)
}

type pbes2CountGetter interface {
	PBES2Count() int
}

type PBES2CountSetter interface {
	SetPBES2Count(p2c int)
}

func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	var p2s []byte
	var p2c int
	if getter, ok := opts.(pbes2SaltInputGetter); ok {
		p2s = getter.PBES2SaltInput()
	}
	if p2s == nil {
		setter, ok := opts.(pbes2SaltInputSetter)
		if !ok {
			return nil, errors.New("pbse2: neither PBES2SaltInput nor SetPBES2SaltInput found")
		}
		p2s = make([]byte, 32)
		if _, err := rand.Read(p2s); err != nil {
			return nil, fmt.Errorf("pkse2: failed initialize p2s: %w", err)
		}
		setter.SetPBES2SaltInput(p2s)
	}
	if getter, ok := opts.(pbes2CountGetter); ok {
		p2c = getter.PBES2Count()
	}
	if p2c == 0 {
		setter, ok := opts.(PBES2CountSetter)
		if !ok {
			return nil, errors.New("pbse2: neither PBES2Count nor SetPBES2Count found")
		}
		p2c = 10000
		setter.SetPBES2Count(p2c)
	}
	return w.wrapKey(p2s, p2c, cek, opts)
}

func (w *KeyWrapper) wrapKey(p2s []byte, p2c int, cek []byte, opts any) (data []byte, err error) {
	name := w.alg.name
	salt := make([]byte, 0, len(name)+len(p2s)+1)
	salt = append(salt, []byte(name)...)
	salt = append(salt, '\x00')
	salt = append(salt, p2s...)
	dk := pbkdf2.Key(w.key, salt, p2c, w.alg.size, w.alg.hash)
	data, err = akw.NewKeyWrapper(dk).WrapKey(cek, opts)
	if err != nil {
		return nil, fmt.Errorf("pbse2: failed to wrap key: %w", err)
	}
	return data, nil
}

func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	p2s, ok := opts.(pbes2SaltInputGetter)
	if !ok {
		return nil, errors.New("pbse2: PBES2SaltInput not found")
	}
	p2c, ok := opts.(pbes2CountGetter)
	if !ok {
		return nil, errors.New("pbse2: PBES2Count not found")
	}
	return w.unwrapKey(p2s.PBES2SaltInput(), p2c.PBES2Count(), data, opts)
}

func (w *KeyWrapper) unwrapKey(p2s []byte, p2c int, data []byte, opts any) ([]byte, error) {
	name := w.alg.name
	salt := make([]byte, 0, len(name)+len(p2s)+1)
	salt = append(salt, []byte(name)...)
	salt = append(salt, '\x00')
	salt = append(salt, p2s...)
	dk := pbkdf2.Key(w.key, salt, p2c, w.alg.size, w.alg.hash)
	cek, err := akw.NewKeyWrapper(dk).UnwrapKey(data, opts)
	if err != nil {
		return nil, fmt.Errorf("pbse2: failed to unwrap key: %w", err)
	}
	return cek, nil
}
