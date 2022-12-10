//go:build go1.20

package ecdhes

import (
	"crypto/ecdh"
	"crypto/ecdsa"
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
		privECDH, err := priv.ECDH()
		if err != nil {
			return nil, err
		}
		pubECDH, err := pubkey.ECDH()
		if err != nil {
			return nil, err
		}
		return privECDH.ECDH(pubECDH)
	case x448.PrivateKey:
		pubkey, ok := pub.(x448.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want x447.PublicKey but got %T", pub)
		}
		return x448.X448(priv[:x448.SeedSize], pubkey)
	case *ecdsa.PrivateKey:
		pubkey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want *ecdsa.PrivateKey but got %T", pub)
		}
		privECDH, err := priv.ECDH()
		if err != nil {
			return nil, err
		}
		pubECDH, err := pubkey.ECDH()
		if err != nil {
			return nil, err
		}
		return privECDH.ECDH(pubECDH)
	case *ecdh.PrivateKey:
		pubkey, ok := pub.(*ecdh.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ecdhes: want *ecdh.PublicKey but got %T", pub)
		}
		return priv.ECDH(pubkey)
	default:
		return nil, fmt.Errorf("ecdhes: unknown private key type: %T", priv)
	}
}
