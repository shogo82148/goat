package jwk

import (
	"bytes"
	"errors"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseEd448Key(d *jsonutils.Decoder, key *Key) {
	x := d.MustBytes("x")
	if len(x) != ed448.PublicKeySize {
		d.SaveError(errors.New("jwk: the parameter x has invalid size"))
		return
	}
	pub := make(ed448.PublicKey, ed448.PublicKeySize)
	copy(pub, x)
	key.pub = pub

	if param, ok := d.GetBytes("d"); ok {
		if len(param) != ed448.SeedSize {
			d.SaveError(errors.New("jwk: the parameter d has invalid size"))
			return
		}
		priv := ed448.NewKeyFromSeed(param)
		if !bytes.Equal([]byte(priv[ed448.SeedSize:]), []byte(pub)) {
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

func encodeEd448Key(e *jsonutils.Encoder, priv ed448.PrivateKey, pub ed448.PublicKey) {
	e.Set("kty", jwa.OKP.String())
	e.Set("crv", jwa.Ed448.String())
	e.SetBytes("x", []byte(pub))
	if priv != nil {
		e.SetBytes("d", []byte(priv[:ed448.SeedSize]))
	}
}

func validateEd448PrivateKey(key ed448.PrivateKey) error {
	if len(key) != ed448.PrivateKeySize {
		return errors.New("jwk: invalid ed448 private key size")
	}
	want := ed448.NewKeyFromSeed(key[:ed448.SeedSize])
	if !bytes.Equal(want, key) {
		return errors.New("jwk: invalid ed448 key pair")
	}
	return nil
}

func validateEd448PublicKey(key ed448.PublicKey) error {
	if len(key) != ed448.PublicKeySize {
		return errors.New("jwk: invalid ed448 public key size")
	}
	return nil
}
