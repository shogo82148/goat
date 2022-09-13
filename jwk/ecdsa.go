package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/shogo82148/goat/jwa"
)

// RFC7518 6.2.2. Parameters for Elliptic Curve Private Keys
func parseEcdsaKey(ctx *decodeContext, key *Key) {
	var privateKey ecdsa.PrivateKey
	crv := jwa.EllipticCurve(must[string](ctx, "crv"))
	switch crv {
	case jwa.P256:
		privateKey.Curve = elliptic.P256()
	case jwa.P384:
		privateKey.Curve = elliptic.P384()
	case jwa.P521:
		privateKey.Curve = elliptic.P521()
	default:
		ctx.error(fmt.Errorf("jwk: unknown crv: %q", crv))
		return
	}

	// parameters for public key
	privateKey.X = new(big.Int).SetBytes(ctx.mustBytes("x"))
	privateKey.Y = new(big.Int).SetBytes(ctx.mustBytes("y"))
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if d, ok := ctx.getBytes("d"); ok {
		privateKey.D = new(big.Int).SetBytes(d)
		key.PrivateKey = &privateKey
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			ctx.error(errors.New("jwk: public key types are mismatch"))
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			ctx.error(errors.New("jwk: public keys are mismatch"))
		}
	}
}
