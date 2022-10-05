package eddsa

import (
	"crypto"
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

func (alg *Algorithm) NewKey(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) sig.Key {
	var key Key
	if priv, ok := privateKey.(ed25519.PrivateKey); ok {
		key.priv = priv
	} else if privateKey != nil {
		return sig.NewInvalidKey(jwa.Ed25519.String(), privateKey, publicKey)
	}
	if pub, ok := publicKey.(ed25519.PublicKey); ok {
		key.pub = pub
	} else if publicKey != nil {
		return sig.NewInvalidKey(jwa.Ed25519.String(), privateKey, publicKey)
	}
	if key.priv != nil && key.pub == nil {
		key.pub = key.priv.Public().(ed25519.PublicKey)
	}
	return &key
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
