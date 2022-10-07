// Package eddsa is a signing algorithm Edwards-Curve Digital Signature Algorithm.
package eddsa

import (
	"crypto/ed25519"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/sig"
)

func New() sig.Algorithm {
	return &Algorithm{}
}

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.EdDSA, New)
}

type Algorithm struct{}

func (alg *Algorithm) NewSigningKey(key sig.Key) sig.SigningKey {
	priv := key.PrivateKey()
	pub := key.PublicKey()

	var k Key
	if key, ok := priv.(ed25519.PrivateKey); ok {
		k.priv = key
	} else if priv != nil {
		return sig.NewInvalidKey(jwa.Ed25519.String(), priv, pub)
	}
	if key, ok := pub.(ed25519.PublicKey); ok {
		k.pub = key
	} else if pub != nil {
		return sig.NewInvalidKey(jwa.Ed25519.String(), priv, pub)
	}
	if k.priv != nil && k.pub == nil {
		k.pub = k.priv.Public().(ed25519.PublicKey)
	}
	return &k
}

type Key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (key *Key) Sign(payload []byte) (signature []byte, err error) {
	signature = ed25519.Sign(key.priv, payload)
	return
}

func (key *Key) Verify(payload, signature []byte) error {
	if !ed25519.Verify(key.pub, payload, signature) {
		return sig.ErrSignatureMismatch
	}
	return nil
}
