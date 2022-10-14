package jwk

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func DecodePEM(data []byte) (key *Key, rest []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("jwk: decoding PEM failed")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		return key, rest, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		return key, rest, nil
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, err := NewPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		return key, rest, nil
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}
		return key, rest, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, err := NewPublicKey(cert.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		key.SetX509CertificateChain([]*x509.Certificate{cert})
		return key, rest, nil
	default:
		return nil, nil, fmt.Errorf("jwk: unknown block type: %s", block.Type)
	}
}
