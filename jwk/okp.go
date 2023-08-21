package jwk

import (
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

// RFC 8037 Section 2.  Key Type "OKP"
func parseOKPKey(d *jsonutils.Decoder, key *Key) {
	crv := jwa.EllipticCurve(d.MustString("crv"))
	switch crv {
	case jwa.Ed25519:
		parseEd25519Key(d, key)
	case jwa.X25519:
		parseX25519Key(d, key)
	case jwa.Ed448:
		parseEd448Key(d, key)
	case jwa.X448:
		parseX448Key(d, key)
	default:
		d.SaveError(fmt.Errorf("jwk: unknown crv: %q", crv))
	}
}
