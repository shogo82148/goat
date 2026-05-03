package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"reflect"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/secp256k1"
)

func init() {
	ec := &ecdsaKeyHandler{}
	RegisterKeyType(jwa.KeyTypeEC, jwa.EllipticCurveP256, ec)
	RegisterKeyType(jwa.KeyTypeEC, jwa.EllipticCurveP384, ec)
	RegisterKeyType(jwa.KeyTypeEC, jwa.EllipticCurveP521, ec)
	RegisterPrivKeyType(reflect.TypeOf((*ecdsa.PrivateKey)(nil)), ec)
	RegisterPubKeyType(reflect.TypeOf((*ecdsa.PublicKey)(nil)), ec)

	sk1 := &secp256k1KeyHandler{}
	RegisterKeyType(jwa.KeyTypeEC, jwa.EllipticCurveSecp256k1, sk1)
	RegisterPrivKeyType(reflect.TypeOf((*secp256k1.PrivateKey)(nil)), sk1)
	RegisterPubKeyType(reflect.TypeOf((*secp256k1.PublicKey)(nil)), sk1)

	ec2 := &ecdhKeyHandler{}
	RegisterPrivKeyType(reflect.TypeOf((*ecdh.PrivateKey)(nil)), ec2)
	RegisterPubKeyType(reflect.TypeOf((*ecdh.PublicKey)(nil)), ec2)
}

// ecdsaKeyHandler handles EC keys with standard P-curves (P-256, P-384, P-521).
type ecdsaKeyHandler struct{}

func (h *ecdsaKeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseEcdsaKey(d, key)
	return d.Err()
}

func (h *ecdsaKeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privECDSA *ecdsa.PrivateKey
	if priv != nil {
		var ok bool
		privECDSA, ok = priv.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for ecdsa: %T", priv)
		}
	}
	var pubECDSA *ecdsa.PublicKey
	if pub != nil {
		var ok bool
		pubECDSA, ok = pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for ecdsa: %T", pub)
		}
	} else if privECDSA != nil {
		pubECDSA = &privECDSA.PublicKey
	}
	if pubECDSA == nil {
		return errors.New("jwk: ECDSA key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeEcdsaKey(e, privECDSA, pubECDSA)
	return e.Err()
}

func (h *ecdsaKeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privECDSA, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil
	}
	switch privECDSA.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return nil, fmt.Errorf("jwk: unknown crv: %q", privECDSA.Curve.Params().Name)
	}
	if _, err := privECDSA.Bytes(); err != nil {
		return nil, err
	}
	return &Key{
		kty:  jwa.KeyTypeEC,
		priv: privECDSA,
		pub:  privECDSA.Public(),
	}, nil
}

func (h *ecdsaKeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubECDSA, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil
	}
	switch pubECDSA.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return nil, fmt.Errorf("jwk: unknown crv: %q", pubECDSA.Curve.Params().Name)
	}
	if _, err := pubECDSA.Bytes(); err != nil {
		return nil, err
	}
	return &Key{
		kty: jwa.KeyTypeEC,
		pub: pubECDSA,
	}, nil
}

// secp256k1KeyHandler handles EC keys with the secp256k1 curve.
type secp256k1KeyHandler struct{}

func (h *secp256k1KeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	d := jsonutils.NewDecoder("jwk", raw)
	parseSecp256k1Key(d, key)
	return d.Err()
}

func (h *secp256k1KeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privSK1 *secp256k1.PrivateKey
	if priv != nil {
		var ok bool
		privSK1, ok = priv.(*secp256k1.PrivateKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for secp256k1: %T", priv)
		}
	}
	var pubSK1 *secp256k1.PublicKey
	if pub != nil {
		var ok bool
		pubSK1, ok = pub.(*secp256k1.PublicKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for secp256k1: %T", pub)
		}
	} else if privSK1 != nil {
		pubSK1 = privSK1.PublicKey()
	}
	if pubSK1 == nil {
		return errors.New("jwk: secp256k1 key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeSecp256k1Key(e, privSK1, pubSK1)
	return e.Err()
}

func (h *secp256k1KeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privSK1, ok := key.(*secp256k1.PrivateKey)
	if !ok {
		return nil, nil
	}
	return &Key{
		kty:  jwa.KeyTypeEC,
		priv: privSK1,
		pub:  privSK1.Public(),
	}, nil
}

func (h *secp256k1KeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubSK1, ok := key.(*secp256k1.PublicKey)
	if !ok {
		return nil, nil
	}
	return &Key{
		kty: jwa.KeyTypeEC,
		pub: pubSK1,
	}, nil
}

// ecdhKeyHandler handles crypto/ecdh keys on the encode/NewKey path.
// On the decode path, EC keys are parsed as *ecdsa.PrivateKey and OKP X25519
// keys are parsed as x25519.PrivateKey; this handler is never used for decoding.
type ecdhKeyHandler struct{}

func (h *ecdhKeyHandler) DecodeKey(raw map[string]any, key *Key) error {
	return errors.New("jwk: ecdh decode is not supported (use EC or OKP key type)")
}

func (h *ecdhKeyHandler) EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error {
	var privECDH *ecdh.PrivateKey
	if priv != nil {
		var ok bool
		privECDH, ok = priv.(*ecdh.PrivateKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for ecdh: %T", priv)
		}
	}
	var pubECDH *ecdh.PublicKey
	if pub != nil {
		var ok bool
		pubECDH, ok = pub.(*ecdh.PublicKey)
		if !ok {
			return fmt.Errorf("jwk: public key type is mismatch for ecdh: %T", pub)
		}
	} else if privECDH != nil {
		pubECDH = privECDH.PublicKey()
	}
	if pubECDH == nil {
		return errors.New("jwk: ECDH key has no public key")
	}
	e := jsonutils.NewEncoder(raw)
	encodeECDHKey(e, privECDH, pubECDH)
	return e.Err()
}

func (h *ecdhKeyHandler) NewPrivateKey(key goat.PrivateKey) (*Key, error) {
	privECDH, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, nil
	}
	switch privECDH.Curve() {
	case ecdh.P256(), ecdh.P384(), ecdh.P521():
		return &Key{
			kty: jwa.KeyTypeEC,
			keyOps: []jwktypes.KeyOp{
				jwktypes.KeyOpDeriveKey,
				jwktypes.KeyOpDeriveBits,
			},
			priv: privECDH,
			pub:  privECDH.PublicKey(),
		}, nil
	case ecdh.X25519():
		return &Key{
			kty: jwa.KeyTypeOKP,
			keyOps: []jwktypes.KeyOp{
				jwktypes.KeyOpDeriveKey,
				jwktypes.KeyOpDeriveBits,
			},
			priv: privECDH,
			pub:  privECDH.PublicKey(),
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown ecdh curve: %s", privECDH.Curve())
	}
}

func (h *ecdhKeyHandler) NewPublicKey(key goat.PublicKey) (*Key, error) {
	pubECDH, ok := key.(*ecdh.PublicKey)
	if !ok {
		return nil, nil
	}
	switch pubECDH.Curve() {
	case ecdh.P256(), ecdh.P384(), ecdh.P521():
		return &Key{
			kty:    jwa.KeyTypeEC,
			keyOps: []jwktypes.KeyOp{jwktypes.KeyOpDeriveBits},
			pub:    pubECDH,
		}, nil
	case ecdh.X25519():
		return &Key{
			kty:    jwa.KeyTypeOKP,
			keyOps: []jwktypes.KeyOp{jwktypes.KeyOpDeriveBits},
			pub:    pubECDH,
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown ecdh curve: %s", pubECDH.Curve())
	}
}

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

func parseSecp256k1Key(d *jsonutils.Decoder, key *Key) {
	// parameters for public key
	x := d.MustBytes("x")
	y := d.MustBytes("y")
	if err := d.Err(); err != nil {
		return
	}
	if len(x) != 32 || len(y) != 32 {
		d.SaveError(errInvalidECDSAParameter)
		return
	}
	buf := make([]byte, 1+2*32)
	buf[0] = 0x04
	copy(buf[1:33], x)
	copy(buf[33:], y)
	pub, err := secp256k1.ParseUncompressedPublicKey(buf)
	if err != nil {
		d.SaveError(errInvalidECDSAParameter)
		return
	}
	key.pub = pub

	// parameters for private key
	var priv *secp256k1.PrivateKey
	if dd, ok := d.GetBytes("d"); ok {
		priv, err = secp256k1.ParseRawPrivateKey(dd)
		if err != nil {
			d.SaveError(errInvalidECDSAParameter)
			return
		}
		key.priv = priv
	}

	// sanity check of the key pair.
	if priv != nil {
		if !priv.PublicKey().Equal(pub) {
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

func encodeECDHKey(e *jsonutils.Encoder, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) {
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
