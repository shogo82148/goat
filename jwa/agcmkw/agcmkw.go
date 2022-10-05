package agcmkw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/keymanage"
)

var a128gcmkw = &Algorithm{
	keySize: 16,
}

func New128() keymanage.Algorithm {
	return a128gcmkw
}

var a192gcmkw = &Algorithm{
	keySize: 24,
}

func New192() keymanage.Algorithm {
	return a192gcmkw
}

var a256gcmkw = &Algorithm{
	keySize: 32,
}

func New256() keymanage.Algorithm {
	return a256gcmkw
}

func init() {
	jwa.RegisterKeyManagementAlgorithm(jwa.A128GCMKW, New128)
	jwa.RegisterKeyManagementAlgorithm(jwa.A192GCMKW, New192)
	jwa.RegisterKeyManagementAlgorithm(jwa.A256GCMKW, New256)
}

var _ keymanage.Algorithm = (*Algorithm)(nil)

type Algorithm struct {
	keySize int
}

type Options struct {
	PrivateKey []byte

	// InitializationVector is RFC7518 Section 4.7.1.1. "iv" (Initialization Vector) Header Parameter.
	// It is the 96-bit IV value used for the key encryption operation.
	InitializationVector []byte

	// AuthenticationTag is RFC7518 Section 4.7.1.2. "tag" (Authentication Tag) Header Parameter.
	AuthenticationTag []byte
}

type initializationVectorGetter interface {
	InitializationVector() []byte
}

type initializationVectorSetter interface {
	SetInitializationVector(iv []byte)
}

type authenticationTagGetter interface {
	AuthenticationTag() []byte
}

type authenticationTagSetter interface {
	SetAuthenticationTag(tag []byte)
}

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(privateKey, publicKey any) keymanage.KeyWrapper {
	priv, ok := privateKey.([]byte)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("rsaoaep: invalid private key type: %T", privateKey))
	}
	if len(priv) != alg.keySize {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: invalid key size: %d-bit key is required, but it is %d-bit", alg.keySize*8, len(priv)*8))
	}
	block, err := aes.NewCipher(priv)
	if err != nil {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: failed to initialize cipher: %w", err))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: failed to initialize gcm: %w", err))
	}
	return &KeyWrapper{
		aead: aead,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	aead cipher.AEAD
}

// WrapKey encrypts CEK.
// It writes the Authentication Tag into opts.AuthenticationTag of NewKeyWrapper.
func (w *KeyWrapper) WrapKey(cek []byte, opts any) ([]byte, error) {
	var iv []byte
	if getter, ok := opts.(initializationVectorGetter); ok {
		iv = getter.InitializationVector()
	}
	if iv == nil {
		setter, ok := opts.(initializationVectorSetter)
		if !ok {
			return nil, errors.New("agcmkw: neither InitializationVector nor SetInitializationVector found")
		}
		iv := make([]byte, w.aead.NonceSize())
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("agcmkw: failed to initialize iv: %w", err)
		}
		setter.SetInitializationVector(iv)
	}
	tag, ok := opts.(authenticationTagSetter)
	if !ok {
		return nil, errors.New("agcmkw: SetAuthenticationTag not found")
	}

	buf := make([]byte, len(cek)+w.aead.Overhead())
	data := w.aead.Seal(buf[:0], iv, cek, []byte{})
	tag.SetAuthenticationTag(data[len(cek):])
	return data[:len(cek)], nil
}

// UnwrapKey decrypts encrypted CEK.
func (w *KeyWrapper) UnwrapKey(data []byte, opts any) ([]byte, error) {
	iv, ok := opts.(initializationVectorGetter)
	if !ok {
		return nil, errors.New("agcmkw: InitializationVector not found")
	}
	tag, ok := opts.(authenticationTagGetter)
	if !ok {
		return nil, errors.New("agcmkw: AuthenticationTag not found")
	}

	tagBytes := tag.AuthenticationTag()
	buf := make([]byte, len(data)+len(tagBytes))
	copy(buf, data)
	copy(buf[len(data):], tagBytes)
	cek, err := w.aead.Open(buf[:0], iv.InitializationVector(), buf, []byte{})
	if err != nil {
		return nil, err
	}
	return cek, nil
}
