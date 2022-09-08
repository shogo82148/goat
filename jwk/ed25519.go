package jwk

import (
	"crypto/ed25519"
	"errors"
)

func parseEd25519Key(ctx *base64Context, data *commonKey, key *Key) (*Key, error) {
	const keySize = ed25519.PrivateKeySize - ed25519.PublicKeySize
	privateKey := make([]byte, ed25519.PrivateKeySize)

	publicKey := ctx.decode(data.X, "x")
	if ctx.err != nil {
		return nil, ctx.err
	}
	if copy(privateKey[keySize:], publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("jwk: the parameter x has invalid size")
	}
	key.PublicKey = ed25519.PublicKey(privateKey[keySize:])

	if data.D != "" {
		d := ctx.decode(data.D, "d")
		if ctx.err != nil {
			return nil, ctx.err
		}
		if copy(privateKey, d) != keySize {
			return nil, errors.New("jwk: the parameter d has invalid size")
		}
		key.PrivateKey = ed25519.PrivateKey(privateKey)
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !ed25519.PublicKey(privateKey[keySize:]).Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return key, nil
}
