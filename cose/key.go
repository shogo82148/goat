package cose

import (
	"bytes"

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

// Key represents a COSE_Key.
type Key struct {
	// Raw is the raw data of CBOR-decoded COSE key.
	// CBOR integers are decoded as cbor.Integer to avoid data loss.
	Raw map[any]any

	kty KeyType
}

// KeyType returns the key type of the key.
func (key *Key) KeyType() KeyType {
	return key.kty
}

func decodeCommonKeyParameters(d *cborutils.Decoder, key *Key) {

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
