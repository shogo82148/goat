package jwk

import (
	"bytes"
	"errors"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x448"
)

func parseX448Key(d *jsonutils.Decoder, key *Key) {
	x := d.MustBytes("x")
	pub := x448.PublicKey(x)
	if err := validateX448PublicKey(pub); err != nil {
		d.SaveError(err)
		return
	}
	key.pub = pub

	if param, ok := d.GetBytes("d"); ok {
		priv := x448.PrivateKey(append(param[:len(param):len(param)], pub...))
		if err := validateX448PrivateKey(priv); err != nil {
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

func encodeX448Key(e *jsonutils.Encoder, priv x448.PrivateKey, pub x448.PublicKey) {
	if err := validateX448PublicKey(pub); err != nil {
		e.SaveError(err)
		return
	}
	e.Set("kty", jwa.OKP.String())
	e.Set("crv", jwa.X448.String())
	e.SetBytes("x", []byte(pub))
	if priv != nil {
		if err := validateX448PrivateKey(priv); err != nil {
			e.SaveError(err)
			return
		}
		e.SetBytes("d", []byte(priv[:x448.SeedSize]))
	}
}

func validateX448PrivateKey(key x448.PrivateKey) error {
	if len(key) != x448.PrivateKeySize {
		return errors.New("jwk: invalid x448 private key size")
	}
	want := x448.NewKeyFromSeed(key[:x448.SeedSize])
	if !bytes.Equal(want, key) {
		return errors.New("jwk: invalid x448 key pair")
	}
	return nil
}

func validateX448PublicKey(key x448.PublicKey) error {
	if len(key) != x448.PublicKeySize {
		return errors.New("jwk: invalid x448 public key size")
	}
	return nil
}
