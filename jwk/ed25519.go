package jwk

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseEd25519Key(d *jsonutils.Decoder, key *Key) {
	x := d.MustBytes("x")
	if len(x) != ed25519.PublicKeySize {
		d.SaveError(errors.New("jwk: the parameter x has invalid size"))
		return
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, x)
	key.pub = pub

	if param, ok := d.GetBytes("d"); ok {
		if len(param) != ed25519.SeedSize {
			d.SaveError(errors.New("jwk: the parameter d has invalid size"))
			return
		}
		priv := ed25519.NewKeyFromSeed(param)
		if !bytes.Equal([]byte(priv[ed25519.SeedSize:]), []byte(pub)) {
			d.SaveError(errors.New("jwk: invalid key pair"))
			return
		}
		key.priv = priv
	}

	// sanity check of the certificate
	if certs := key.x5c; len(certs) > 0 {
		cert := certs[0]
		publicKey := cert.PublicKey
		if !pub.Equal(publicKey) {
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

func validateEd25519PrivateKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("jwk: invalid ed25519 private key size")
	}
	want := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(want, key[ed25519.SeedSize:]) {
		return errors.New("jwk: invalid ed25519 key pair")
	}
	return nil
}

func validateEd25519PublicKey(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("jwk: invalid ed25519 public key size")
	}
	return nil
}
