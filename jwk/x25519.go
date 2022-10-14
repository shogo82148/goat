package jwk

import (
	"bytes"
	"errors"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x25519"
)

func parseX25519Key(d *jsonutils.Decoder, key *Key) {
	x := d.MustBytes("x")
	pub := x25519.PublicKey(x)
	if err := validateX25519PublicKey(pub); err != nil {
		d.SaveError(err)
		return
	}
	key.pub = pub

	if param, ok := d.GetBytes("d"); ok {
		priv := x25519.PrivateKey(append(param[:len(param):len(param)], pub...))
		if err := validateX25519PrivateKey(priv); err != nil {
			d.SaveError(err)
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

func encodeX25519Key(e *jsonutils.Encoder, priv x25519.PrivateKey, pub x25519.PublicKey) {
	if err := validateX25519PublicKey(pub); err != nil {
		e.SaveError(err)
		return
	}
	e.Set("kty", jwa.OKP.String())
	e.Set("crv", jwa.X25519.String())
	e.SetBytes("x", []byte(pub))
	if priv != nil {
		if err := validateX25519PrivateKey(priv); err != nil {
			e.SaveError(err)
			return
		}
		e.SetBytes("d", []byte(priv[:x25519.SeedSize]))
	}
}

func validateX25519PrivateKey(key x25519.PrivateKey) error {
	if len(key) != x25519.PrivateKeySize {
		return errors.New("jwk: invalid x25519 private key size")
	}
	want := x25519.NewKeyFromSeed(key[:x25519.SeedSize])
	if !bytes.Equal(want, key) {
		return errors.New("jwk: invalid x25519 key pair")
	}
	return nil
}

func validateX25519PublicKey(key x25519.PublicKey) error {
	if len(key) != x25519.PublicKeySize {
		return errors.New("jwk: invalid x25519 public key size")
	}
	return nil
}
