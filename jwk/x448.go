package jwk

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/x448"
)

func init() {
	h := &x448KeyHandler{}
	RegisterKeyType(jwa.KeyTypeOKP, jwa.EllipticCurveX448, h)
	RegisterPrivKeyType(reflect.TypeOf(x448.PrivateKey(nil)), h)
	RegisterPubKeyType(reflect.TypeOf(x448.PublicKey(nil)), h)
}

type x448KeyHandler struct{}

func (h *x448KeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseX448Key(d, key)
	return d.Err()
}

func (h *x448KeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privX x448.PrivateKey
	if priv != nil {
		var ok bool
		privX, ok = priv.(x448.PrivateKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for x448")
		}
	}
	var pubX x448.PublicKey
	if pub != nil {
		var ok bool
		pubX, ok = pub.(x448.PublicKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for x448")
		}
	} else if privX != nil {
		pubX = privX.Public().(x448.PublicKey)
	}
	if pubX == nil {
		return errors.New("jwk: x448 key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeX448Key(e, privX, pubX)
	return e.Err()
}

func (h *x448KeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privX, ok := key.(x448.PrivateKey)
	if !ok {
		return nil, nil
	}
	if err := validateX448PrivateKey(privX); err != nil {
		return nil, err
	}
	return &Key{
		kty:  jwa.KeyTypeOKP,
		priv: privX,
		pub:  privX.Public(),
	}, nil
}

func (h *x448KeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubX, ok := key.(x448.PublicKey)
	if !ok {
		return nil, nil
	}
	if err := validateX448PublicKey(pubX); err != nil {
		return nil, err
	}
	return &Key{
		kty: jwa.KeyTypeOKP,
		pub: pubX,
	}, nil
}

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
	e.Set("kty", jwa.KeyTypeOKP.String())
	e.Set("crv", jwa.EllipticCurveX448.String())
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
