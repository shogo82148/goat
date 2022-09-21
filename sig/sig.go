// package sig provides interface for signature.
package sig

import (
	"errors"
	"fmt"
	"reflect"
)

// Algorithm is an algorithm for signature.
type Algorithm interface {
	// NewKey returns a new key for privateKey and publicKey.
	// If Algorithm uses symmetric keys, publicKey is nil.
	NewKey(privateKey, publicKey any) Key
}

// Key is a key for signature.
type Key interface {
	Sign(payload []byte) (signature []byte, err error)
	Verify(payload, signature []byte) error
}

// ErrSignatureMismatch is an error for unavailable hash.
var ErrHashUnavailable = errors.New("sig: hash is unavailable")

// ErrSignUnavailable means sign method is not unavailable.
var ErrSignUnavailable = errors.New("sig: sign method is unavailable")

// ErrSignatureMismatch is signature mismatch error.
var ErrSignatureMismatch = errors.New("sig: signature mismatch")

type invalidKey struct {
	alg            string
	privateKeyType reflect.Type
	publicKeyType  reflect.Type
}

// NewInvalidKey returns a new key that returns an error for all
// Sign and Verify operations.
func NewInvalidKey(alg string, privateKey, publicKey any) Key {
	t1 := reflect.TypeOf(privateKey)
	t2 := reflect.TypeOf(publicKey)
	return &invalidKey{
		alg:            alg,
		privateKeyType: t1,
		publicKeyType:  t2,
	}
}

// Sign implements Key.
func (key *invalidKey) Sign(payload []byte) (signature []byte, err error) {
	return nil, key
}

// Verify implements Key.
func (key *invalidKey) Verify(payload, signature []byte) error {
	return key
}

// Error implements error.
func (key *invalidKey) Error() string {
	return fmt.Sprintf(
		"sig: invalid key type for algorithm %s: %s, %s",
		key.alg, key.privateKeyType.String(), key.publicKeyType.String(),
	)
}
