// Package rsaoaep implements a Key Encryption Algorithm RSA-OAEP.
package rsaoaep

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var alg = &Algorithm{
	hash: crypto.SHA1,
}

func New() keymanage.Algorithm {
	return alg
}

var alg256 = &Algorithm{
	hash: crypto.SHA256,
}

func New256() keymanage.Algorithm {
	return alg256
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.RSA_OAEP, New)
	jwa.RegisterKeyManagementAlgorithm(jwa.RSA_OAEP_256, New256)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	hash crypto.Hash
}

func (alg *Algorithm) NewKeyWrapper(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) keymanage.KeyWrapper {
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
			alg:  alg,
			priv: priv,
			pub:  &priv.PublicKey,
		}
	}

	return &KeyWrapper{
		alg: alg,
		pub: pub,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)
var label = []byte{}

type KeyWrapper struct {
	alg  *Algorithm
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	hash := w.alg.hash.New()
	return rsa.EncryptOAEP(hash, rand.Reader, w.pub, cek, label)
}

func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	hash := w.alg.hash.New()
	return rsa.DecryptOAEP(hash, rand.Reader, w.priv, data, label)
}
