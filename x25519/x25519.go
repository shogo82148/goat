// Package x25519 implements the X25519 Elliptic Curve Diffie-Hellman algorithm.
// See RFC 8032.
package x25519

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"io"
	"strconv"

	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// PublicKey is the type of X25519 public keys.
type PublicKey []byte

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}

// PrivateKey is the type of X25519 private keys.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv, xx) == 1
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:32])
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
	publicKey, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	copy(privateKey, seed)
	copy(privateKey[32:], publicKey)
	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("x25519: bad seed length: " + strconv.Itoa(l))
	}

	privateKey := make([]byte, PrivateKeySize)
	publicKey, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	copy(privateKey, seed)
	copy(privateKey[32:], publicKey)
	return privateKey
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are slices of 32 bytes.
func X25519(scalar, point []byte) ([]byte, error) {
	return curve25519.X25519(scalar, point)
}
