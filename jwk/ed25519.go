package jwk

import (
	"crypto/ed25519"
	"errors"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseEd25519Key(d *jsonutils.Decoder, key *Key) {
	privateKey := make([]byte, ed25519.PrivateKeySize)

	publicKey := d.MustBytes("x")
	if copy(privateKey[ed25519.SeedSize:], publicKey) != ed25519.PublicKeySize {
		d.SaveError(errors.New("jwk: the parameter x has invalid size"))
		return
	}
	key.PublicKey = ed25519.PublicKey(privateKey[ed25519.SeedSize:])

	if param, ok := d.GetBytes("d"); ok {
		if len(param) != ed25519.SeedSize {
			d.SaveError(errors.New("jwk: the parameter d has invalid size"))
			return
		}
		copy(privateKey, param)
		key.PrivateKey = ed25519.PrivateKey(privateKey)
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey := cert.PublicKey
		if !ed25519.PublicKey(privateKey[ed25519.SeedSize:]).Equal(publicKey) {
			d.SaveError(errors.New("jwk: public keys are mismatch"))
			return
		}
	}
}

func encodeEd25519Key(e *jsonutils.Encoder, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	e.Set("kty", jwa.OKP.String())
	e.Set("crv", jwa.Ed25519.String())
	e.SetBytes("x", []byte(pub))
	if priv != nil {
		e.SetBytes("d", []byte(priv[:ed25519.SeedSize]))
	}
}
