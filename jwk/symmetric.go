package jwk

import (
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

func parseSymmetricKey(d *jsonutils.Decoder, key *Key) {
	privateKey := d.MustBytes("k")
	key.PrivateKey = privateKey
}

func encodeSymmetricKey(e *jsonutils.Encoder, priv []byte) {
	e.Set("kty", jwa.Oct.String())
	e.SetBytes("k", priv)
}
