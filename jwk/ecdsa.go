package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/secp256k1"
)

// RFC 7518 6.2.2. Parameters for Elliptic Curve Private Keys
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
	case jwa.Secp256k1:
		curve = secp256k1.Curve()
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
	key.pub = &pub
	if err := validateEcdsaPublicKey(&pub); err != nil {
		d.SaveError(err)
		return
	}

	// parameters for private key
	if dd, ok := d.GetBigInt("d"); ok {
		priv := ecdsa.PrivateKey{
			PublicKey: pub,
			D:         dd,
		}
		if err := validateEcdsaPrivateKey(&priv); err != nil {
			d.SaveError(err)
			return
		}
		key.priv = &priv
	}

	// sanity check of the certificate
	if certs := key.x5c; len(certs) > 0 {
		cert := certs[0]
		if !pub.Equal(cert.PublicKey) {
			d.SaveError(errors.New("jwk: public keys are mismatch"))
		}
	}
}

// RFC 7518 6.2.2. Parameters for Elliptic Curve Private Keys
func encodeEcdsaKey(e *jsonutils.Encoder, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
	if err := validateEcdsaPublicKey(pub); err != nil {
		e.SaveError(err)
		return
	}
	e.Set("kty", jwa.EC.String())
	switch pub.Curve {
	case elliptic.P256():
		e.Set("crv", jwa.P256.String())
	case elliptic.P384():
		e.Set("crv", jwa.P384.String())
	case elliptic.P521():
		e.Set("crv", jwa.P521.String())
	case secp256k1.Curve():
		e.Set("crv", jwa.Secp256k1.String())
	default:
		panic("not reach")
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	e.SetFixedBigInt("x", pub.X, size)
	e.SetFixedBigInt("y", pub.Y, size)
	if priv != nil {
		if !priv.PublicKey.Equal(pub) {
			e.SaveError(errors.New("jwk: invalid ecdsa key pair"))
			return
		}
		if err := validateEcdsaPrivateKey(priv); err != nil {
			e.SaveError(err)
			return
		}
		e.SetFixedBigInt("d", priv.D, size)
	}
}

// sanity check of private key
func validateEcdsaPrivateKey(key *ecdsa.PrivateKey) error {
	if err := validateEcdsaPublicKey(&key.PublicKey); err != nil {
		return err
	}
	xx, yy := key.ScalarBaseMult(key.D.Bytes())
	if xx.Cmp(key.X) != 0 || yy.Cmp(key.Y) != 0 {
		return errors.New("jwk: invalid ecdsa key pair")
	}
	return nil
}

// sanity check of public key
func validateEcdsaPublicKey(key *ecdsa.PublicKey) error {
	switch key.Curve {
	case elliptic.P256():
	case elliptic.P384():
	case elliptic.P521():
	case secp256k1.Curve():
	default:
		return errors.New("jwk: unknown elliptic curve of ecdsa public key")
	}
	if key.X.Sign() == 0 || key.Y.Sign() == 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
		return fmt.Errorf("jwk: invalid parameter of ecdsa public key")
	}
	return nil
}
