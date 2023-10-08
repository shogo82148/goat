package jws

import (
	"context"

	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

// KeyFinder finds a signing key for the JWS message.
type KeyFinder interface {
	FindKey(ctx context.Context, protected, unprotected *Header) (key sig.SigningKey, err error)
}

// FindKeyFunc is an adapter to allow the use of ordinary functions as KeyFinder.
type FindKeyFunc func(ctx context.Context, protected, unprotected *Header) (key sig.SigningKey, err error)

func (f FindKeyFunc) FindKey(ctx context.Context, protected, unprotected *Header) (key sig.SigningKey, err error) {
	return f(ctx, protected, unprotected)
}

// JWKKeyFinder returns a specific signing key.
type JWKKeyFinder struct {
	JWK *jwk.Key
}

func (f *JWKKeyFinder) FindKey(ctx context.Context, protected, unprotected *Header) (key sig.SigningKey, err error) {
	alg := protected.Algorithm().New()
	return alg.NewSigningKey(f.JWK), nil
}
