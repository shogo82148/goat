package jwk

import (
	"crypto/mlkem"

	"github.com/shogo82148/goat/internal/jsonutils"
)

func encodeMLKEM768Key(e *jsonutils.Encoder, priv *mlkem.DecapsulationKey768, pub *mlkem.EncapsulationKey768) {
	// TODO: implement me!
}

func encodeMLKEM1024Key(e *jsonutils.Encoder, priv *mlkem.DecapsulationKey1024, pub *mlkem.EncapsulationKey1024) {
	// TODO: implement me!
}

func parseAKPKey(d *jsonutils.Decoder, key *Key) {
	// TODO: implement me!
}
