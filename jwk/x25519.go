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
	if len(x) != x25519.PublicKeySize {
		d.SaveError(errors.New("jwk: the parameter x has invalid size"))
		return
	}
	pub := make(x25519.PublicKey, x25519.PublicKeySize)
	copy(pub, x)
	key.pub = pub

	if param, ok := d.GetBytes("d"); ok {
		if len(param) != x25519.SeedSize {
			d.SaveError(errors.New("jwk: the parameter d has invalid size"))
			return
		}
		priv := x25519.NewKeyFromSeed(param)
		if !bytes.Equal([]byte(priv[x25519.SeedSize:]), []byte(pub)) {
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

func encodex25519Key(e *jsonutils.Encoder, priv x25519.PrivateKey, pub x25519.PublicKey) {
	e.Set("kty", jwa.OKP.String())
	e.Set("crv", jwa.X25519.String())
	e.SetBytes("x", []byte(pub))
	if priv != nil {
		e.SetBytes("d", []byte(priv[:x25519.SeedSize]))
	}
}
