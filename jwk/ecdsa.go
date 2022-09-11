package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/shogo82148/goat/jwa"
)

// RFC7518 6.2.2. Parameters for Elliptic Curve Private Keys
func parseEcdsaKey(data *commonKey) (*Key, error) {
	ctx := newEcdsaContext(data)
	key, err := data.decode(ctx)
	if err != nil {
		return nil, err
	}

	var privateKey ecdsa.PrivateKey
	switch data.Crv {
	case jwa.P256:
		privateKey.Curve = elliptic.P256()
	case jwa.P384:
		privateKey.Curve = elliptic.P384()
	case jwa.P521:
		privateKey.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwk: unknown elliptic curve: %q", data.Crv)
	}

	// parameters for public key
	privateKey.X = new(big.Int).SetBytes(ctx.decode(data.X, "x"))
	privateKey.Y = new(big.Int).SetBytes(ctx.decode(data.Y, "y"))
	key.PublicKey = &privateKey.PublicKey

	// parameters for private key
	if data.D != "" {
		privateKey.D = new(big.Int).SetBytes(ctx.decode(data.D, "d"))
		key.PrivateKey = &privateKey
	}

	if ctx.err != nil {
		return nil, ctx.err
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return key, nil
}

func newEcdsaContext(key *commonKey) *base64Context {
	var size int
	if len(key.X) > size {
		size = len(key.X)
	}
	if len(key.Y) > size {
		size = len(key.Y)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	if len(key.X5t) > size {
		size = len(key.X5t)
	}
	if len(key.X5tS256) > size {
		size = len(key.X5tS256)
	}
	return newBase64Context(size)
}
