package jwk

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x25519"
)

func init() {
	h := &x25519KeyHandler{}
	RegisterKeyType(jwa.KeyTypeOKP, jwa.EllipticCurveX25519, h)
	RegisterPrivKeyType(reflect.TypeOf(x25519.PrivateKey(nil)), h)
	RegisterPubKeyType(reflect.TypeOf(x25519.PublicKey(nil)), h)
}

type x25519KeyHandler struct{}

func (h *x25519KeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseX25519Key(d, key)
	return d.Err()
}

func (h *x25519KeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privX x25519.PrivateKey
	if priv != nil {
		var ok bool
		privX, ok = priv.(x25519.PrivateKey)
		if !ok {
			return errors.New("jwk: private key type is mismatch for x25519")
		}
	}
	var pubX x25519.PublicKey
	if pub != nil {
		var ok bool
		pubX, ok = pub.(x25519.PublicKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for x25519")
		}
	} else if privX != nil {
		pubX = privX.Public().(x25519.PublicKey)
	}
	if pubX == nil {
		return errors.New("jwk: x25519 key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeX25519Key(e, privX, pubX)
	return e.Err()
}

func (h *x25519KeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privX, ok := key.(x25519.PrivateKey)
	if !ok {
		return nil, nil
	}
	if err := validateX25519PrivateKey(privX); err != nil {
		return nil, err
	}
	return &Key{
		kty:  jwa.KeyTypeOKP,
		priv: privX,
		pub:  privX.Public(),
	}, nil
}

func (h *x25519KeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubX, ok := key.(x25519.PublicKey)
	if !ok {
		return nil, nil
	}
	if err := validateX25519PublicKey(pubX); err != nil {
		return nil, err
	}
	return &Key{
		kty: jwa.KeyTypeOKP,
		pub: pubX,
	}, nil
}

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
	e.Set("kty", jwa.KeyTypeOKP.String())
	e.Set("crv", jwa.EllipticCurveX25519.String())
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
