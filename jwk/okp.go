package jwk

import (
	"fmt"

	"github.com/shogo82148/goat/jwa"
)

// RFC8037 2.  Key Type "OKP"
func parseOKPKey(ctx *decodeContext, key *Key) {
	crv := jwa.EllipticCurve(must[string](ctx, "crv"))
	switch crv {
	case jwa.Ed25519:
		parseEd25519Key(ctx, key)
	default:
		ctx.error(fmt.Errorf("jwk: unknown crv: %q", crv))
	}
}
