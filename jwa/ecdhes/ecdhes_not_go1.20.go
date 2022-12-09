//go:build !go1.20

package ecdhes

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
)

func deriveZ(priv, pub any) ([]byte, error) {
	switch priv := priv.(type) {
	case x25519.PrivateKey:
		pubkey, ok := pub.(x25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want x25519.PublicKey but got %T", pub)
		}
		return x25519.X25519(priv[:x25519.SeedSize], pubkey)
	case x448.PrivateKey:
		pubkey, ok := pub.(x448.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want z447.PublicKey but got %T", pub)
		}
		return x448.X448(priv[:x448.SeedSize], pubkey)
	case *ecdsa.PrivateKey:
		pubkey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want *ecdsa.PrivateKey but got %T", pub)
		}
		crv := priv.Curve
		if pubkey.Curve != crv || !crv.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, errors.New("ecdhes: public key must be on the same curve as private key")
		}
		z, _ := crv.ScalarMult(pubkey.X, pubkey.Y, priv.D.Bytes())
		size := (crv.Params().BitSize + 7) / 8
		buf := make([]byte, size)
		return z.FillBytes(buf), nil
	default:
		return nil, fmt.Errorf("ecdhes: unknown private key type: %T", priv)
	}
}
