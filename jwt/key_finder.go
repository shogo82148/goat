package jwt

import (
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	// FindKey finds the key used for signing.
	// e.g, you can return a key corresponding to the KID.
	FindKey(header *jws.Header) (key sig.SigningKey, err error)
}

// FindKeyFunc is an adapter to allow the use of ordinary functions as KeyFinder interfaces.
// If f is a function with the appropriate signature, FindKeyFunc(f) is a KeyFinder that calls f.
type FindKeyFunc func(header *jws.Header) (key sig.SigningKey, err error)

// FindKey calls f(header).
func (f FindKeyFunc) FindKey(header *jws.Header) (sig.SigningKey, error) {
	return f(header)
}

// Token is a decoded JWT token.
type Token struct {
	Header *jws.Header
	Claims *Claims
}

type JWKSKeyFinder struct {
	JWKS *jwk.Set
}

func (f *JWKSKeyFinder) FindKey(header *jws.Header) (sig.SigningKey, error) {
	kid := header.KeyID()
	if kid == "" {
		return nil, errors.New("jwt: kid is not set")
	}
	key, found := f.JWKS.Find(kid)
	if !found {
		return nil, errors.New("jwt: key not found")
	}
	alg, err := guessAlg(key, header)
	if err != nil {
		return nil, err
	}
	return alg.NewSigningKey(key), nil
}

type JWKKeyFiner struct {
	Key *jwk.Key
}

func (f *JWKKeyFiner) FindKey(header *jws.Header) (sig.SigningKey, error) {
	alg, err := guessAlg(f.Key, header)
	if err != nil {
		return nil, err
	}
	return alg.NewSigningKey(f.Key), nil
}

func guessAlg(key *jwk.Key, header *jws.Header) (sig.Algorithm, error) {
	algSupported := jwa.SignatureAlgorithm(key.Algorithm())
	algRequested := header.Algorithm()
	if algSupported == "" && algRequested == "" {
		return nil, errors.New("jwt: failed to guess signature algorithm")
	}
	if algSupported != "" {
		if algRequested != "" && algRequested != algSupported {
			return nil, fmt.Errorf("jwt: requested alg %q is not supported", algRequested)
		}
		return algSupported.New(), nil
	}
	return algRequested.New(), nil
}
