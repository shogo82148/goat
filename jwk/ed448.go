package jwk

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func init() {
	h := &ed448KeyHandler{}
	RegisterKeyType(jwa.KeyTypeOKP, jwa.EllipticCurveEd448, h)
	RegisterPrivKeyType(reflect.TypeOf(ed448.PrivateKey(nil)), h)
	RegisterPubKeyType(reflect.TypeOf(ed448.PublicKey(nil)), h)
}

type ed448KeyHandler struct{}

func (h *ed448KeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseEd448Key(d, key)
	return d.Err()
}

func (h *ed448KeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privED ed448.PrivateKey
	if priv != nil {
		var ok bool
		privED, ok = priv.(ed448.PrivateKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for ed448")
		}
	}
	var pubED ed448.PublicKey
	if pub != nil {
		var ok bool
		pubED, ok = pub.(ed448.PublicKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for ed448")
		}
	} else if privED != nil {
		pubED = privED.Public().(ed448.PublicKey)
	}
	if pubED == nil {
		return errors.New("jwk: ed448 key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeEd448Key(e, privED, pubED)
	return e.Err()
}

func (h *ed448KeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privED, ok := key.(ed448.PrivateKey)
	if !ok {
		return nil, nil
	}
	if err := validateEd448PrivateKey(privED); err != nil {
		return nil, err
	}
	return &Key{
		kty:  jwa.KeyTypeOKP,
		priv: privED,
		pub:  privED.Public(),
	}, nil
}

func (h *ed448KeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubED, ok := key.(ed448.PublicKey)
	if !ok {
		return nil, nil
	}
	if err := validateEd448PublicKey(pubED); err != nil {
		return nil, err
	}
	return &Key{
		kty: jwa.KeyTypeOKP,
		pub: pubED,
	}, nil
}

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
	e.Set("kty", jwa.KeyTypeOKP.String())
	e.Set("crv", jwa.EllipticCurveEd448.String())
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
