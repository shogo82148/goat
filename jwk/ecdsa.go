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
	var curve elliptic.Curve
	crv := jwa.EllipticCurve(d.MustString("crv"))
	switch crv {
	case jwa.P256:
		curve = elliptic.P256()
	case jwa.P384:
		curve = elliptic.P384()
	case jwa.P521:
		curve = elliptic.P521()
	default:
		d.SaveError(fmt.Errorf("jwk: unknown crv: %q", crv))
		return
	}

	// parameters for public key
	x := d.MustBigInt("x")
	y := d.MustBigInt("y")
	if err := d.Err(); err != nil {
		return
	}
	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	key.PublicKey = &pub
	if !curve.IsOnCurve(x, y) {
		d.SaveError(fmt.Errorf("jwk: invalid ecdsa %s public key", crv))
	}

	// parameters for private key
	if dd, ok := d.GetBigInt("d"); ok {
		priv := ecdsa.PrivateKey{
			PublicKey: pub,
			D:         dd,
		}
		key.PrivateKey = &priv

		// sanity check of private key
		xx, yy := priv.ScalarBaseMult(dd.Bytes())
		if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
			d.SaveError(fmt.Errorf("jwk: invalid ecdsa %s private key", crv))
		}
	}

	// sanity check of the certificate
	if certs := key.x5c; len(certs) > 0 {
		cert := certs[0]
		if !pub.Equal(cert.PublicKey) {
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
