package jwk

import "github.com/shogo82148/goat/internal/jsonutils"

func parseSymmetricKey(d *jsonutils.Decoder, key *Key) {
	privateKey := d.MustBytes("k")
	key.PrivateKey = privateKey
}
