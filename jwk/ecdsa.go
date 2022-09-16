package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
)

// RFC7518 6.2.2. Parameters for Elliptic Curve Private Keys
func parseEcdsaKey(d *jsonutils.Decoder, key *Key) {
	var privateKey ecdsa.PrivateKey
	crv := jwa.EllipticCurve(d.MustString("crv"))
	switch crv {
	case jwa.P256:
		privateKey.Curve = elliptic.P256()
	case jwa.P384:
		privateKey.Curve = elliptic.P384()
	case jwa.P521:
		privateKey.Curve = elliptic.P521()
	default:
		d.Must(fmt.Errorf("jwk: unknown crv: %q", crv))
		return
	}

	// parameters for public key
	privateKey.X = d.MustBigInt("x")
	privateKey.Y = d.MustBigInt("y")
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if d, ok := d.GetBigInt("d"); ok {
		privateKey.D = d
		key.PrivateKey = &privateKey
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			d.Must(errors.New("jwk: public key types are mismatch"))
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			d.Must(errors.New("jwk: public keys are mismatch"))
		}
	}
}
