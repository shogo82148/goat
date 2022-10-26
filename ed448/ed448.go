package ed448

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"io"
	"strconv"

	"github.com/shogo82148/goat/internal/edwards448"
	"golang.org/x/crypto/sha3"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 57
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 114
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 114
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 57
)

// PublicKey is the type of Ed448 public keys.
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}

// PrivateKey is the type of X448 private keys.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[57:])
	return PublicKey(publicKey)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(priv, xx)
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:57])
	return seed
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)

	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[57:])

	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("x448: bad seed length: " + strconv.Itoa(l))
	}

	h := make([]byte, 114)
	sha3.ShakeSum256(h, seed)

	s, err := edwards448.NewScalar().SetBytesWithClamping(h[:57])
	if err != nil {
		panic(err)
	}
	p := new(edwards448.Point).ScalarBaseMult(s)
	copy(privateKey, seed)
	copy(privateKey[57:], p.Bytes())
}
