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
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("rsapkcs1v15: invalid option type: %T", opts))
	}
	if key.PrivateKey != nil {
		return &KeyWrapper{
			priv: key.PrivateKey,
			pub:  &key.PrivateKey.PublicKey,
		}
	}
	return &KeyWrapper{
		priv: key.PrivateKey,
		pub:  key.PublicKey,
	}
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
