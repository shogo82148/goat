package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/secp256k1"
)

var errInvalidECDSAParameter = errors.New("jwk: invalid parameter of ecdsa")

// RFC 7518 Section 6.2.2. Parameters for Elliptic Curve Private Keys
func parseEcdsaKey(d *jsonutils.Decoder, key *Key) {
	var curve elliptic.Curve
	var size int
	crv := jwa.EllipticCurve(d.MustString("crv"))
	switch crv {
	case jwa.EllipticCurveP256:
		curve = elliptic.P256()
		size = 32
	case jwa.EllipticCurveP384:
		curve = elliptic.P384()
		size = 48
	case jwa.EllipticCurveP521:
		curve = elliptic.P521()
		size = 66
	case jwa.EllipticCurveSecp256k1:
		curve = secp256k1.Curve()
		// TODO: implement parsing of secp256k1 keys.
		d.SaveError(errors.New("jwk: not implemented"))
		return
	default:
		d.SaveError(fmt.Errorf("jwk: unknown crv: %q", crv))
		return
	}

	// parameters for private key
	var priv *ecdsa.PrivateKey
	if dd, ok := d.GetBytes("d"); ok {
		var err error
		priv, err = ecdsa.ParseRawPrivateKey(curve, dd)
		if err != nil {
			d.SaveError(errInvalidECDSAParameter)
			return
		}
		key.priv = priv
	}

	// parameters for public key
	x := d.MustBytes("x")
	y := d.MustBytes("y")
	if err := d.Err(); err != nil {
		return
	}
	if len(x) != size || len(y) != size {
		d.SaveError(errInvalidECDSAParameter)
		return
	}
	buf := make([]byte, 1+2*size)
	buf[0] = 0x04 // uncompressed form
	copy(buf[1:1+size], x)
	copy(buf[1+size:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, buf)
	if err != nil {
		d.SaveError(errInvalidECDSAParameter)
		return
	}
	key.pub = pub

	// sanity check of the key pair.
	if priv != nil {
		if !priv.PublicKey.Equal(pub) {
			d.SaveError(errInvalidECDSAParameter)
			return
		}
	}

	// sanity check of the certificate.
	if certs := key.x5c; len(certs) > 0 {
		cert := certs[0]
		if !pub.Equal(cert.PublicKey) {
			d.SaveError(errInvalidECDSAParameter)
			return
		}
	}
}

// RFC 7518 Section 6.2.2. Parameters for Elliptic Curve Private Keys
func encodeEcdsaKey(e *jsonutils.Encoder, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
	var size int
	e.Set("kty", jwa.KeyTypeEC.String())
	switch pub.Curve {
	case elliptic.P256():
		e.Set("crv", jwa.EllipticCurveP256.String())
		size = 32
	case elliptic.P384():
		e.Set("crv", jwa.EllipticCurveP384.String())
		size = 48
	case elliptic.P521():
		e.Set("crv", jwa.EllipticCurveP521.String())
		size = 66
	case secp256k1.Curve(): //nolint:staticcheck // for backward compatibility
		encodeEcdsaKeySecp256k1(e, priv, pub)
		return
	default:
		e.SaveError(fmt.Errorf("jwk: unknown crv: %q", pub.Curve.Params().Name))
		return
	}

	// encode the public key.
	data, err := pub.Bytes()
	if err != nil {
		e.SaveError(errInvalidECDSAParameter)
		return
	}
	if len(data) != 1+2*size || data[0] != 0x04 {
		e.SaveError(errInvalidECDSAParameter)
		return
	}
	e.SetBytes("x", data[1:1+size])
	e.SetBytes("y", data[1+size:])

	// encode the private key.
	if priv != nil {
		if !priv.PublicKey.Equal(pub) {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		data, err := priv.Bytes()
		if err != nil {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		if len(data) != size {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		e.SetBytes("d", data)
	}
}

func encodeEcdsaKeySecp256k1(e *jsonutils.Encoder, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) {
	if pub.Curve != secp256k1.Curve() { //nolint:staticcheck // for backward compatibility
		panic("jwk: invalid curve for secp256k1 key")
	}

	// encode the public key.
	e.Set("crv", jwa.EllipticCurveSecp256k1.String())
	e.SetFixedBigInt("x", pub.X, 32) //nolint:staticcheck // for backward compatibility
	e.SetFixedBigInt("y", pub.Y, 32) //nolint:staticcheck // for backward compatibility

	// encode the private key.
	if priv != nil {
		if !priv.PublicKey.Equal(pub) {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		e.SetFixedBigInt("d", priv.D, 32) //nolint:staticcheck // for backward compatibility
	}
}

func encodeSecp256k1Key(e *jsonutils.Encoder, priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) {
	e.Set("kty", jwa.KeyTypeEC.String())
	e.Set("crv", jwa.EllipticCurveSecp256k1.String())

	// encode the public key.
	data, err := pub.Bytes()
	if err != nil {
		e.SaveError(errInvalidECDSAParameter)
		return
	}
	if len(data) != 1+2*32 || data[0] != 0x04 {
		e.SaveError(errInvalidECDSAParameter)
		return
	}
	e.SetBytes("x", data[1:33])
	e.SetBytes("y", data[33:])

	// encode the private key.
	if priv != nil {
		if !priv.PublicKey().Equal(pub) {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		data, err := priv.Bytes()
		if err != nil {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		if len(data) != 32 {
			e.SaveError(errInvalidECDSAParameter)
			return
		}
		e.SetBytes("d", data)
	}
}

func encodeECDHKey(e *jsonutils.Encoder, priv *ecdhPrivateKey, pub *ecdhPublicKey) {
	switch pub.Curve() {
	case ecdh.P256():
		e.Set("kty", jwa.KeyTypeEC.String())
		e.Set("crv", jwa.EllipticCurveP256.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:32+1])
		e.SetBytes("y", data[32+1:])
	case ecdh.P384():
		e.Set("kty", jwa.KeyTypeEC.String())
		e.Set("crv", jwa.EllipticCurveP384.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:48+1])
		e.SetBytes("y", data[48+1:])
	case ecdh.P521():
		e.Set("kty", jwa.KeyTypeEC.String())
		e.Set("crv", jwa.EllipticCurveP521.String())
		data := pub.Bytes()
		e.SetBytes("x", data[1:66+1])
		e.SetBytes("y", data[66+1:])
	case ecdh.X25519():
		e.Set("kty", jwa.KeyTypeOKP.String())
		e.Set("crv", jwa.EllipticCurveX25519.String())
		e.SetBytes("x", pub.Bytes())
	default:
		e.SaveError(errors.New("jwk: unknown crv"))
		return
	}

	if priv != nil {
		e.SetBytes("d", priv.Bytes())
	}
}
