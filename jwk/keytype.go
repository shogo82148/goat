package jwk

import (
	"reflect"
	"sync"

	"github.com/shogo82148/goat"
	"github.com/shogo82148/goat/jwa"
)

// KeyHandler handles JWK encoding and decoding for a specific key type.
// Implementations are registered via [RegisterKeyType], [RegisterPrivKeyType],
// and [RegisterPubKeyType].
//
// Third-party packages can implement new key types by implementing this interface
// and registering it in an init function, similar to database/sql drivers.
type KeyHandler interface {
	// DecodeKey decodes a JWK from the raw JSON map and populates the key's
	// private and/or public key fields by calling key.SetPrivateKey or
	// key.SetPublicKey. The raw map contains all JSON parameters including
	// "kty", "crv", and the key-specific parameters.
	DecodeKey(raw map[string]any, key *Key) error

	// EncodeKey encodes the private and/or public key into the raw map.
	// The handler must set "kty" (and "crv" for OKP/EC key types).
	// priv is nil when encoding a public-key-only JWK.
	EncodeKey(raw map[string]any, priv goat.PrivateKey, pub goat.PublicKey) error

	// NewPrivateKey wraps a Go private key into a JWK [Key].
	// It returns (nil, nil) if this handler does not handle the given key type.
	NewPrivateKey(key goat.PrivateKey) (*Key, error)

	// NewPublicKey wraps a Go public key into a JWK [Key].
	// It returns (nil, nil) if this handler does not handle the given key type.
	NewPublicKey(key goat.PublicKey) (*Key, error)
}

type ktyAndCrv struct {
	kty jwa.KeyType
	crv jwa.EllipticCurve
}

var (
	mu           sync.RWMutex
	keyTypeMap   = make(map[ktyAndCrv]KeyHandler)
	privKeyTypes = make(map[reflect.Type]KeyHandler)
	pubKeyTypes  = make(map[reflect.Type]KeyHandler)
)

// RegisterKeyType registers a [KeyHandler] for the given JWK key type and curve.
// For key types that do not use a curve (e.g., RSA, oct), pass an empty string
// for crv.
//
// This function is not safe to call concurrently with other registrations and is
// intended to be called from package init functions.
func RegisterKeyType(kty jwa.KeyType, crv jwa.EllipticCurve, h KeyHandler) {
	mu.Lock()
	defer mu.Unlock()
	keyTypeMap[ktyAndCrv{kty, crv}] = h
}

// RegisterPrivKeyType registers a [KeyHandler] for encoding and creating JWKs
// from the given Go private key type. privType should be the [reflect.Type] of
// the concrete private key type (e.g., reflect.TypeOf((*rsa.PrivateKey)(nil))).
//
// This function is not safe to call concurrently with other registrations and is
// intended to be called from package init functions.
func RegisterPrivKeyType(privType reflect.Type, h KeyHandler) {
	mu.Lock()
	defer mu.Unlock()
	privKeyTypes[privType] = h
}

// RegisterPubKeyType registers a [KeyHandler] for encoding and creating JWKs
// from the given Go public key type. pubType should be the [reflect.Type] of
// the concrete public key type (e.g., reflect.TypeOf((*rsa.PublicKey)(nil))).
//
// This function is not safe to call concurrently with other registrations and is
// intended to be called from package init functions.
func RegisterPubKeyType(pubType reflect.Type, h KeyHandler) {
	mu.Lock()
	defer mu.Unlock()
	pubKeyTypes[pubType] = h
}

func lookupKeyType(kty jwa.KeyType, crv jwa.EllipticCurve) (KeyHandler, bool) {
	mu.RLock()
	defer mu.RUnlock()
	h, ok := keyTypeMap[ktyAndCrv{kty, crv}]
	return h, ok
}

func lookupPrivKeyType(t reflect.Type) (KeyHandler, bool) {
	mu.RLock()
	defer mu.RUnlock()
	h, ok := privKeyTypes[t]
	return h, ok
}

func lookupPubKeyType(t reflect.Type) (KeyHandler, bool) {
	mu.RLock()
	defer mu.RUnlock()
	h, ok := pubKeyTypes[t]
	return h, ok
}
