//go:build go1.20
// +build go1.20

package x25519

import "crypto/ecdh"

// ECDH returns pub as a [crypto/ecdh.PublicKey].
func (pub PublicKey) ECDH() (*ecdh.PublicKey, error) {
	c := ecdh.X25519()
	return c.NewPublicKey(pub)
}

// ECDH returns priv as a [crypto/ecdh.PrivateKey].
func (priv PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	c := ecdh.X25519()
	return c.NewPrivateKey(priv[:SeedSize])
}
