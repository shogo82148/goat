package cose

import (
	"bytes"
	"fmt"

	"github.com/shogo82148/go-cbor"
	"github.com/shogo82148/goat/internal/cborutils"
)

// KeyType represents a COSE_Key type.
type KeyType int64

const (
	// KeyTypeReserved is a reserved key type.
	KeyTypeReserved KeyType = 0

	// KeyTypeOKP is an Octet Key Pair.
	KeyTypeOKP KeyType = 1

	// KeyTypeEC2 is an Elliptic Curve Key Pair.
	KeyTypeEC2 KeyType = 2

	// KeyTypeRSA is an RSA Key Pair.
	KeyTypeRSA KeyType = 3

	// KeyTypeSymmetric is a Symmetric Key.
	KeyTypeSymmetric KeyType = 4

	// KeyTypeHSS_LMS is public key for HSS/LMS hash-based digital signature.
	KeyTypeHSS_LMS KeyType = 5

	// KeyTypeWalnutDSA is WalnutDSA public key.
	KeyTypeWalnutDSA KeyType = 6
)

const (
	keyTypeOKP       = "OKP"
	keyTypeEC2       = "EC2"
	keyTypeRSA       = "RSA"
	keyTypeSymmetric = "Symmetric"
	keyTypeHSS_LMS   = "HSS-LMS"
	keyTypeWalnutDSA = "WalnutDSA"
)

// String returns the string representation of the key type.
func (kty KeyType) String() string {
	switch kty {
	case KeyTypeOKP:
		return keyTypeOKP
	case KeyTypeEC2:
		return keyTypeEC2
	case KeyTypeRSA:
		return keyTypeRSA
	case KeyTypeSymmetric:
		return keyTypeSymmetric
	case KeyTypeHSS_LMS:
		return keyTypeHSS_LMS
	case KeyTypeWalnutDSA:
		return keyTypeWalnutDSA
	default:
		return fmt.Sprintf("KeyType(%d)", kty)
	}
}

func parseKeyType(s string) (KeyType, error) {
	switch s {
	case keyTypeOKP:
		return KeyTypeOKP, nil
	case keyTypeEC2:
		return KeyTypeEC2, nil
	case keyTypeRSA:
		return KeyTypeRSA, nil
	case keyTypeSymmetric:
		return KeyTypeSymmetric, nil
	case keyTypeHSS_LMS:
		return KeyTypeHSS_LMS, nil
	case keyTypeWalnutDSA:
		return KeyTypeWalnutDSA, nil
	default:
		return KeyTypeReserved, fmt.Errorf("unknown key type: %s", s)
	}
}

// https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
const (
	keyLabelKeyType   = 1 // Identification of the key type
	keyLabelKeyID     = 2 // Key identification value - match to kid in message
	keyLabelAlgorithm = 3 // Key usage restriction to this algorithm
	keyLabelKeyOps    = 4 // Restrict set of permissible operations
	keyLabelBaseIV    = 5 // Base IV to be XORed with Partial IVs
)

type Curve int64

const (
	CurveP256      Curve = 1 // NIST P-256 also known as secp256r1
	CurveP384      Curve = 2 // NIST P-384 also known as secp384r1
	CurveP521      Curve = 3 // NIST P-521 also known as secp521r1
	CurveX25519    Curve = 4 // X25519 for use w/ ECDH only
	CurveX448      Curve = 5 // X448 for use w/ ECDH only
	CurveEd25519   Curve = 6 // Ed25519 for use w/ EdDSA only
	CurveEd448     Curve = 7 // Ed448 for use w/ EdDSA only
	CurveSecp256k1 Curve = 8 // SECG secp256k1 curve
)

const (
	curveP256      = "P-256"
	curveP384      = "P-384"
	curveP521      = "P-521"
	curveX25519    = "X25519"
	curveX448      = "X448"
	curveEd25519   = "Ed25519"
	curveEd448     = "Ed448"
	curveSecp256k1 = "secp256k1"
)

func (curve Curve) String() string {
	switch curve {
	case CurveP256:
		return curveP256
	case CurveP384:
		return curveP384
	case CurveP521:
		return curveP521
	case CurveX25519:
		return curveX25519
	case CurveX448:
		return curveX448
	case CurveEd25519:
		return curveEd25519
	case CurveEd448:
		return curveEd448
	case CurveSecp256k1:
		return curveSecp256k1
	default:
		return fmt.Sprintf("Curve(%d)", curve)
	}
}

func parseCurve(s string) (Curve, error) {
	switch s {
	case curveP256:
		return CurveP256, nil
	case curveP384:
		return CurveP384, nil
	case curveP521:
		return CurveP521, nil
	case curveX25519:
		return CurveX25519, nil
	case curveX448:
		return CurveX448, nil
	case curveEd25519:
		return CurveEd25519, nil
	case curveEd448:
		return CurveEd448, nil
	case curveSecp256k1:
		return CurveSecp256k1, nil
	default:
		return 0, fmt.Errorf("unknown curve: %s", s)
	}
}

// Key represents a COSE_Key.
type Key struct {
	// Raw is the raw data of CBOR-decoded COSE key.
	// CBOR integers are decoded as cbor.Integer to avoid data loss.
	Raw map[any]any

	kty KeyType
	kid []byte

	crv Curve
	x   []byte
	y   []byte
	d   []byte
}

// KeyType returns the key type of the key.
func (key *Key) KeyType() KeyType {
	return key.kty
}

// KeyID returns the key ID of the key.
func (key *Key) KeyID() []byte {
	return key.kid
}

// Curve returns the curve of the key.
func (key *Key) Curve() Curve {
	return key.crv
}

// X returns the x coordinate of the key.
func (key *Key) X() []byte {
	return key.x
}

// Y returns the y coordinate of the key.
func (key *Key) Y() []byte {
	return key.y
}

// D returns the private key of the key.
func (key *Key) D() []byte {
	return key.d
}

func decodeCommonKeyParameters(d *cborutils.Decoder, key *Key) {
	// kty
	if kty, ok := d.GetInteger(keyLabelKeyType); ok {
		i64, err := kty.Int64()
		if err != nil {
			d.SaveError(err)
			return
		}
		key.kty = KeyType(i64)
	} else if kty, ok := d.GetString(keyLabelKeyType); ok {
		kty, err := parseKeyType(kty)
		if err != nil {
			d.SaveError(err)
			return
		}
		key.kty = kty
	} else {
		d.SaveError(fmt.Errorf("missing key type"))
	}

	// kid
	if kid, ok := d.GetBytes(keyLabelKeyID); ok {
		key.kid = kid
	}
}

// ParseKey parses a COSE_Key.
func ParseKey(data []byte) (*Key, error) {
	var raw map[any]any
	dec := cbor.NewDecoder(bytes.NewReader(data))
	dec.UseAnyKey()
	dec.UseInteger()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return ParseMap(raw)
}

// ParseMap parses a COSE_Key from a map.
func ParseMap(raw map[any]any) (*Key, error) {
	key := &Key{
		Raw: raw,
	}
	d := cborutils.NewDecoder("cose", raw)
	decodeCommonKeyParameters(d, key)
	if d.Err() != nil {
		return nil, d.Err()
	}

	switch key.kty {
	case KeyTypeOKP:
		// crv
		if crv, ok := d.GetInteger(-1); ok {
			i64, err := crv.Int64()
			if err != nil {
				d.SaveError(err)
			}
			key.crv = Curve(i64)
		} else if crv, ok := d.GetString(-1); ok {
			crv, err := parseCurve(crv)
			if err != nil {
				d.SaveError(err)
			}
			key.crv = crv
		} else {
			d.SaveError(fmt.Errorf("missing curve"))
		}

		// x
		key.x = d.MustBytes(-2)

		// d
		key.d = d.MustBytes(-4)

	case KeyTypeEC2:
		// crv
		if crv, ok := d.GetInteger(-1); ok {
			i64, err := crv.Int64()
			if err != nil {
				d.SaveError(err)
			}
			key.crv = Curve(i64)
		} else if crv, ok := d.GetString(-1); ok {
			crv, err := parseCurve(crv)
			if err != nil {
				d.SaveError(err)
			}
			key.crv = crv
		} else {
			d.SaveError(fmt.Errorf("missing curve"))
		}

		// x
		key.x = d.MustBytes(-2)

		// y
		key.y = d.MustBytes(-3)

		// d
		key.d = d.MustBytes(-4)
	case KeyTypeRSA:
	case KeyTypeSymmetric:
	case KeyTypeHSS_LMS:
	case KeyTypeWalnutDSA:
	default:
		return nil, fmt.Errorf("unknown key type: %v", key.kty)
	}

	return key, nil
}

// KeySet represents a COSE_KeySet.
type KeySet struct {
	Keys []*Key
}

// ParseKeySet parses a COSE_KeySet.
func ParseKeySet(data []byte) (*KeySet, error) {
	var raw []map[any]any
	dec := cbor.NewDecoder(bytes.NewReader(data))
	dec.UseAnyKey()
	dec.UseInteger()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	keySet := &KeySet{
		Keys: make([]*Key, len(raw)),
	}
	for i, rawKey := range raw {
		key, err := ParseMap(rawKey)
		if err != nil {
			return nil, err
		}
		keySet.Keys[i] = key
	}

	return keySet, nil
}
