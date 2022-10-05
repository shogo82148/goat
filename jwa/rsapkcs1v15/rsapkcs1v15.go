package rsapkcs1v15

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

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

type Options struct {
	// PrivateKey is used for UnwrapKey.
	PrivateKey *rsa.PrivateKey

	// PublicKey is used for WrapKey.
	PublicKey *rsa.PublicKey
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
func (alg *Algorithm) NewKeyWrapper(privateKey, publicKey any) keymanage.KeyWrapper {
	priv, ok := privateKey.(*rsa.PrivateKey)
	if !ok && privateKey != nil {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("rsaoaep: invalid private key type: %T", privateKey))
	}
	pub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("rsaoaep: invalid public key type: %T", publicKey))
	}

	if priv != nil {
		return &KeyWrapper{
			priv: priv,
			pub:  &priv.PublicKey,
		}
	}

	return &KeyWrapper{
		pub: pub,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, w.pub, cek)
}

func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, w.priv, data)
}
