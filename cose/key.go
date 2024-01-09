package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/shogo82148/go-cbor"
	"github.com/shogo82148/goat/internal/cborutils"
	"github.com/shogo82148/goat/secp256k1"
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

const (
	curveP256      = 1 // NIST P-256 also known as secp256r1
	curveP384      = 2 // NIST P-384 also known as secp384r1
	curveP521      = 3 // NIST P-521 also known as secp521r1
	curveX25519    = 4 // X25519 for use w/ ECDH only
	curveX448      = 5 // X448 for use w/ ECDH only
	curveEd25519   = 6 // Ed25519 for use w/ EdDSA only
	curveEd448     = 7 // Ed448 for use w/ EdDSA only
	curveSecp256k1 = 8 // SECG secp256k1 curve
)

const (
	curveNameP256      = "P-256"
	curveNameP384      = "P-384"
	curveNameP521      = "P-521"
	curveNameX25519    = "X25519"
	curveNameX448      = "X448"
	curveNameEd25519   = "Ed25519"
	curveNameEd448     = "Ed448"
	curveNameSecp256k1 = "secp256k1"
)

// Key represents a COSE_Key.
type Key struct {
	// Raw is the raw data of CBOR-decoded COSE key.
	// CBOR integers are decoded as cbor.Integer to avoid data loss.
	Raw map[any]any

	kty KeyType
	kid []byte

	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// KeyType returns the key type of the key.
func (key *Key) KeyType() KeyType {
	return key.kty
}

// KeyID returns the key ID of the key.
func (key *Key) KeyID() []byte {
	return key.kid
}

// PrivateKey returns the private key of the key.
func (key *Key) PrivateKey() crypto.PrivateKey {
	return key.priv
}

// PublicKey returns the public key of the key.
func (key *Key) PublicKey() crypto.PublicKey {
	return key.pub
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
		// TODO: implement me
		return nil, fmt.Errorf("not implemented yet")

	case KeyTypeEC2:
		parseEcdsaKey(d, key)

	case KeyTypeRSA:
		// TODO: implement me
		return nil, fmt.Errorf("not implemented yet")

	case KeyTypeSymmetric:
		// TODO: implement me
		return nil, fmt.Errorf("not implemented yet")

	case KeyTypeHSS_LMS:
		// TODO: implement me
		return nil, fmt.Errorf("not implemented yet")

	case KeyTypeWalnutDSA:
		// TODO: implement me
		return nil, fmt.Errorf("not implemented yet")

	default:
		return nil, fmt.Errorf("unknown key type: %v", key.kty)
	}

	if d.Err() != nil {
		return nil, d.Err()
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

func parseEcdsaKey(d *cborutils.Decoder, key *Key) {
	// curve
	var curve elliptic.Curve
	if crv, ok := d.GetInteger(-1); ok {
		i64, err := crv.Int64()
		if err != nil {
			d.SaveError(err)
		}
		switch i64 {
		case curveP256:
			curve = elliptic.P256()
		case curveP384:
			curve = elliptic.P384()
		case curveP521:
			curve = elliptic.P521()
		case curveSecp256k1:
			curve = secp256k1.Curve()
		}
	} else if crv, ok := d.GetString(-1); ok {
		switch crv {
		case curveNameP256:
			curve = elliptic.P256()
		case curveNameP384:
			curve = elliptic.P384()
		case curveNameP521:
			curve = elliptic.P521()
		case curveNameSecp256k1:
			curve = secp256k1.Curve()
		}
	} else {
		d.SaveError(fmt.Errorf("missing curve"))
	}

	// parameters for public key
	x := d.MustBytes(-2)
	y := d.MustBytes(-3)
	if err := d.Err(); err != nil {
		return
	}
	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	key.pub = &pub
	if err := validateEcdsaPublicKey(&pub); err != nil {
		d.SaveError(err)
		return
	}

	// parameters for private key
	if dd, ok := d.GetBytes(-4); ok {
		priv := ecdsa.PrivateKey{
			PublicKey: pub,
			D:         new(big.Int).SetBytes(dd),
		}
		if err := validateEcdsaPrivateKey(&priv); err != nil {
			d.SaveError(err)
			return
		}
		key.priv = &priv
	}
}

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
