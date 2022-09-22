// package sig provides interface for signature.
package sig

import (
	"errors"
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
	priv := "nil"
	if key.privateKeyType != nil {
		priv = key.privateKeyType.String()
	}
	pub := "nil"
	if key.publicKeyType != nil {
		pub = key.publicKeyType.String()
	}
	return "sig: invalid key type for algorithm " + key.alg + ": " + priv + ", " + pub
}

type errKey struct {
	err error
}

// NewInvalidKey returns a new key that returns an error for all
// Sign and Verify operations.
func NewErrorKey(err error) Key {
	return &errKey{
		err: err,
	}
}

// Sign implements Key.
func (key *errKey) Sign(payload []byte) (signature []byte, err error) {
	return nil, key.err
}

// Verify implements Key.
func (key *errKey) Verify(payload, signature []byte) error {
	return key.err
}
