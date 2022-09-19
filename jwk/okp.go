package jwk

import (
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

// RFC8037 2.  Key Type "OKP"
func parseOKPKey(d *jsonutils.Decoder, key *Key) {
	crv := jwa.EllipticCurve(d.MustString("crv"))
	switch crv {
	case jwa.Ed25519:
		parseEd25519Key(d, key)
	default:
		d.NewError(fmt.Errorf("jwk: unknown crv: %q", crv))
	}
}
