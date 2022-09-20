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
		d.SaveError(fmt.Errorf("jwk: unknown crv: %q", crv))
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
		if !privateKey.PublicKey.Equal(cert.PublicKey) {
			d.SaveError(errors.New("jwk: public keys are mismatch"))
		}
	}
}

// RFC7518 6.2.2. Parameters for Elliptic Curve Private Keys
func encodeEcdsaKey(e *jsonutils.Encoder, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
	e.Set("kty", jwa.EC.String())
	switch pub.Curve {
	case elliptic.P256():
		e.Set("crv", jwa.P256.String())
	case elliptic.P384():
		e.Set("crv", jwa.P384.String())
	case elliptic.P521():
		e.Set("crv", jwa.P521.String())
	default:
		e.SaveError(fmt.Errorf("jwk: unknown elliptic curve %v", pub.Curve))
	}
	e.SetBigInt("x", pub.X)
	e.SetBigInt("y", pub.Y)
	if priv != nil {
		e.SetBigInt("d", priv.D)
	}
}
