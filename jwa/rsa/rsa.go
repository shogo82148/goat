package rsa

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{}

func New() keymanage.Algorithm {
	return alg
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.RSA1_5, New)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct{}

func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	switch opts := opts.(type) {
	case *rsa.PrivateKey:
		return &KeyWrapper{
			priv: opts,
			pub:  &opts.PublicKey,
		}
	case *rsa.PublicKey:
		return &KeyWrapper{
			pub: opts,
		}
	}
	return &KeyWrapper{}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, w.pub, cek)
}

func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, w.priv, data)
}
