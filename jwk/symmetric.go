package jwk

import (
	"errors"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func init() {
	h := &symmetricKeyHandler{}
	RegisterKeyType(jwa.KeyTypeOct, "", h)
	RegisterPrivKeyType(reflect.TypeOf([]byte(nil)), h)
}

type symmetricKeyHandler struct{}

func (h *symmetricKeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseSymmetricKey(d, key)
	return d.Err()
}

func (h *symmetricKeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	privBytes, ok := priv.([]byte)
	if !ok {
		return errors.New("jwk: unexpected private key type for symmetric key")
	}
	if pub != nil {
		return errors.New("jwk: public key is not allowed for symmetric keys")
	}
	e := jsonutils.NewEncoder(raw)
	encodeSymmetricKey(e, privBytes)
	return e.Err()
}

func (h *symmetricKeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privBytes, ok := key.([]byte)
	if !ok {
		return nil, nil
	}
	return &Key{
		kty:  jwa.KeyTypeOct,
		priv: append([]byte(nil), privBytes...),
	}, nil
}

func (h *symmetricKeyHandler) NewPublicKey(_ goat.PublicKey) (*Key, error) {
	return nil, nil
}

func parseSymmetricKey(d *jsonutils.Decoder, key *Key) {
	privateKey := d.MustBytes("k")
	key.priv = privateKey
}

func encodeSymmetricKey(e *jsonutils.Encoder, priv []byte) {
	e.Set("kty", jwa.KeyTypeOct.String())
	e.SetBytes("k", priv)
}
