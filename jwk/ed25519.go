package jwk

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func init() {
	h := &ed25519KeyHandler{}
	RegisterKeyType(jwa.KeyTypeOKP, jwa.EllipticCurveEd25519, h)
	RegisterPrivKeyType(reflect.TypeOf(ed25519.PrivateKey(nil)), h)
	RegisterPubKeyType(reflect.TypeOf(ed25519.PublicKey(nil)), h)
}

type ed25519KeyHandler struct{}

func (h *ed25519KeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseEd25519Key(d, key)
	return d.Err()
}

func (h *ed25519KeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privED ed25519.PrivateKey
	if priv != nil {
		var ok bool
		privED, ok = priv.(ed25519.PrivateKey)
		if !ok {
			return errors.New("jwk: private key type is mismatch for ed25519")
		}
	}
	var pubED ed25519.PublicKey
	if pub != nil {
		var ok bool
		pubED, ok = pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("jwk: public key type is mismatch for ed25519")
		}
	} else if privED != nil {
		pubED = privED.Public().(ed25519.PublicKey)
	}
	if pubED == nil {
		return errors.New("jwk: ed25519 key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeEd25519Key(e, privED, pubED)
	return e.Err()
}

func (h *ed25519KeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privED, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil
	}
	if err := validateEd25519PrivateKey(privED); err != nil {
		return nil, err
	}
	return &Key{
		kty:  jwa.KeyTypeOKP,
		priv: privED,
		pub:  privED.Public(),
	}, nil
}

func (h *ed25519KeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubED, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, nil
	}
	if err := validateEd25519PublicKey(pubED); err != nil {
		return nil, err
	}
	return &Key{
		kty: jwa.KeyTypeOKP,
		pub: pubED,
	}, nil
}

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
	e.Set("kty", jwa.KeyTypeOKP.String())
	e.Set("crv", jwa.EllipticCurveEd25519.String())
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
	if !bytes.Equal(want, key) {
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
