package agcmkw

import (
	"crypto/aes"
	"crypto/cipher"
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

// NewKeyWrapper implements [github.com/shogo82148/goat/keymanage.Algorithm].
// opts must be a pointer to [Options].
func (alg *Algorithm) NewKeyWrapper(opts any) keymanage.KeyWrapper {
	key, ok := opts.(*Options)
	if !ok {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: invalid option type: %T", opts))
	}
	if len(key.PrivateKey) != alg.keySize {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: invalid key size: %d-bit key is required, but it is %d-bit", alg.keySize*8, len(key.PrivateKey)*8))
	}
	block, err := aes.NewCipher(key.PrivateKey)
	if err != nil {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: failed to initialize cipher: %w", err))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: failed to initialize gcm: %w", err))
	}

	if len(key.InitializationVector) != aead.NonceSize() {
		return keymanage.NewInvalidKeyWrapper(fmt.Errorf("agcmkw: invalid iv size: %d-bit key is required, but it is %d-bit", aead.NonceSize()*8, len(key.InitializationVector)*8))
	}
	return &KeyWrapper{
		aead: aead,
		opts: key,
	}
}

var _ keymanage.KeyWrapper = (*KeyWrapper)(nil)

type KeyWrapper struct {
	aead cipher.AEAD
	opts *Options
}

// WrapKey encrypts CEK.
// It writes the Authentication Tag into opts.AuthenticationTag of NewKeyWrapper.
func (w *KeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	buf := make([]byte, len(cek)+w.aead.Overhead())
	data := w.aead.Seal(buf[:0], w.opts.InitializationVector, cek, []byte{})
	w.opts.AuthenticationTag = append(w.opts.AuthenticationTag[:0], data[len(cek):]...)
	return data[:len(cek)], nil
}

// UnwrapKey decrypts encrypted CEK.
func (w *KeyWrapper) UnwrapKey(data []byte) ([]byte, error) {
	buf := make([]byte, len(data)+len(w.opts.AuthenticationTag))
	copy(buf, data)
	copy(buf[len(data):], w.opts.AuthenticationTag)
	cek, err := w.aead.Open(buf[:0], w.opts.InitializationVector, buf, []byte{})
	if err != nil {
		return nil, err
	}
	return cek, nil
}
