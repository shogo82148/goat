package jwk

import (
	"crypto/ed25519"
	"errors"
)

func parseEd25519Key(ctx *decodeContext, key *Key) {
	const keySize = ed25519.PrivateKeySize - ed25519.PublicKeySize
	privateKey := make([]byte, ed25519.PrivateKeySize)

	publicKey := ctx.mustBytes("x")
	if copy(privateKey[keySize:], publicKey) != ed25519.PublicKeySize {
		ctx.error(errors.New("jwk: the parameter x has invalid size"))
		return
	}
	key.PublicKey = ed25519.PublicKey(privateKey[keySize:])

	if d, ok := ctx.getBytes("d"); ok {
		if copy(privateKey, d) != keySize {
			ctx.error(errors.New("jwk: the parameter d has invalid size"))
			return
		}
		key.PrivateKey = ed25519.PrivateKey(privateKey)
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain; len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			ctx.error(errors.New("jwk: public key types are mismatch"))
			return
		}
		if !ed25519.PublicKey(privateKey[keySize:]).Equal(publicKey) {
			ctx.error(errors.New("jwk: public keys are mismatch"))
			return
		}
	}
}
