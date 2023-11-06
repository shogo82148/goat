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

// Key represents a COSE_Key.
type Key struct {
	// Raw is the raw data of CBOR-decoded COSE key.
	// CBOR integers are decoded as cbor.Integer to avoid data loss.
	Raw map[any]any

	kty KeyType
	kid []byte
}

// KeyType returns the key type of the key.
func (key *Key) KeyType() KeyType {
	return key.kty
}

// KeyID returns the key ID of the key.
func (key *Key) KeyID() []byte {
	return key.kid
}

func decodeCommonKeyParameters(d *cborutils.Decoder, key *Key) {
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
