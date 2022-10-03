package pbes2

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/shogo82148/goat/internal/jsonutils"
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

func (w *KeyWrapper) WrapKey(cek []byte) (map[string]any, []byte, error) {
	p2s := make([]byte, 32)
	if _, err := rand.Read(p2s); err != nil {
		return nil, nil, fmt.Errorf("pkse2: failed initialize p2s: %w", err)
	}
	p2c := 10000
	return w.WrapKeyOpts(p2s, p2c, cek)
}

func (w *KeyWrapper) WrapKeyOpts(p2s []byte, p2c int, cek []byte) (header map[string]any, data []byte, err error) {
	name := w.alg.name
	salt := make([]byte, 0, len(name)+len(p2s))
	salt = append(salt, []byte(name)...)
	salt = append(salt, '\x00')
	dk := pbkdf2.Key(w.key, salt, p2c, w.alg.size, w.alg.hash)
	_, data, err = akw.NewKeyWrapper(dk).WrapKey(cek)
	if err != nil {
		return nil, nil, fmt.Errorf("pbse2: failed to wrap key: %w", err)
	}
	header = map[string]any{
		jwa.PBES2SaltInput: base64.RawURLEncoding.EncodeToString(salt),
		jwa.PBES2Count:     p2c,
	}
	return header, data, nil
}

func (w *KeyWrapper) UnwrapKey(header map[string]any, data []byte) ([]byte, error) {
	d := jsonutils.NewDecoder("pbse2", header)
	p2s := d.MustBytes(jwa.PBES2SaltInput)
	p2c := d.MustInt64(jwa.PBES2Count)
	if err := d.Err(); err != nil {
		return nil, err
	}
	if p2c <= 0 || p2c > math.MaxInt {
		return nil, errors.New("pbse2: p2c is out of range")
	}
	return w.UnwrapKeyOpts(p2s, int(p2c), data)
}

func (w *KeyWrapper) UnwrapKeyOpts(p2s []byte, p2c int, data []byte) ([]byte, error) {
	name := w.alg.name
	salt := make([]byte, 0, len(name)+len(p2s))
	salt = append(salt, []byte(name)...)
	salt = append(salt, '\x00')
	dk := pbkdf2.Key(w.key, salt, p2c, w.alg.size, w.alg.hash)
	cek, err := akw.NewKeyWrapper(dk).UnwrapKey(nil, data)
	if err != nil {
		return nil, fmt.Errorf("pbse2: failed to unwrap key: %w", err)
	}
	return cek, nil
}
