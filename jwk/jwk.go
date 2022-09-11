// The package jwk handles JSON Web Key [RFC7517].
package jwk

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jwa"
)

// Key is a JSON Web Key.
type Key struct {
	// KeyType is RFC7517 4.1. "kty" (Key Type) Parameter.
	KeyType jwa.KeyType

	// PublicKeyUse is RFC7517 4.2. "use" (Public Key Use) Parameter.
	PublicKeyUse string

	// KeyOperations is RFC7517 4.3. "key_ops" (Key Operations) Parameter.
	KeyOperations []string

	// Algorithm is RFC7517 4.4. "alg" (Algorithm) Parameter.
	Algorithm jwa.KeyAlgorithm

	// KeyID is RFC7517 4.5. "kid" (Key ID) Parameter.
	KeyID string

	// X509URL is RFC7517 4.6. "x5u" (X.509 URL) Parameter.
	X509URL string

	// X509CertificateChain is RFC7517 4.7. "x5c" (X.509 Certificate Chain) Parameter.
	X509CertificateChain []*x509.Certificate

	// X509CertificateSHA1 is RFC7517 4.8. "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter.
	X509CertificateSHA1 []byte

	// X509CertificateSHA256 is RFC7517 4.9. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter.
	X509CertificateSHA256 []byte

	// PrivateKey is the private key.
	// If the key doesn't contain any private key, it returns nil.
	PrivateKey any

	// PublicKey is the public key.
	// If the key doesn't contain any public key, it returns nil.
	PublicKey any
}

type commonKey struct {
	// RFC7517 4.1. "kty" (Key Type) Parameter
	Kty jwa.KeyType `json:"kty"`

	// RFC7517 4.2. "use" (Public Key Use) Parameter
	Use string `json:"use,omitempty"`

	// RFC7517 4.3. "key_ops" (Key Operations) Parameter
	KeyOps []string `json:"key_ops,omitempty"`

	// RFC7517 4.4. "alg" (Algorithm) Parameter
	Alg jwa.KeyAlgorithm `json:"alg,omitempty"`

	// RFC7517 4.5. "kid" (Key ID) Parameter
	Kid string `json:"kid,omitempty"`

	// RFC7517 4.6. "x5u" (X.509 URL) Parameter
	X5u string `json:"x5u,omitempty"`

	// RFC7517 4.7. "x5c" (X.509 Certificate Chain) Parameter
	X5c [][]byte `json:"x5c,omitempty"`

	// RFC7517 4.8. "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter
	X5t string `json:"x5t,omitempty"`

	// RFC7517 4.9. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter
	X5tS256 string `json:"x5t#S256,omitempty"`

	// key type specific parameters
	Crv string `json:"crv,omitempty"`
	D   string `json:"d,omitempty"`
	Dp  string `json:"dp,omitempty"`
	Dq  string `json:"dq,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
	N   string `json:"n,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	Qi  string `json:"qi,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Oth []struct {
		R string `json:"r,omitempty"`
		D string `json:"d,omitempty"`
		T string `json:"t,omitempty"`
	} `json:"oth,omitempty"`
}

func (key *commonKey) decode(ctx *base64Context) (*Key, error) {
	// decode the certificates
	certs := make([]*x509.Certificate, 0, len(key.X5c))
	for _, der := range key.X5c {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("jwk: failed to parse x5c")
		}
		certs = append(certs, cert)
	}

	// check thumbprints
	var x5t, x5tS256 []byte
	if key.X5t != "" {
		if len(certs) == 0 && key.X5u == "" {
			return nil, errors.New("jwk: the certificate is not found")
		}
		got := sha1.Sum(key.X5c[0])
		want := ctx.decode(key.X5t, "x5t")
		if ctx.err != nil {
			return nil, ctx.err
		}
		if subtle.ConstantTimeCompare(got[:], want) == 0 {
			return nil, errors.New("jwk: the sha-1 thumbprint of the certificate is mismatch")
		}
		x5t = append([]byte(nil), want...)
	}
	if key.X5tS256 != "" {
		if len(key.X5c) == 0 && key.X5u == "" {
			return nil, errors.New("jwk: the certificate is not found")
		}
		got := sha256.Sum256(key.X5c[0])
		want := ctx.decode(key.X5t, "x5t#S256")
		if ctx.err != nil {
			return nil, ctx.err
		}
		if subtle.ConstantTimeCompare(got[:], want) == 0 {
			return nil, errors.New("jwk: the sha-256 thumbprint of the certificate is mismatch")
		}
		x5tS256 = append([]byte(nil), want...)
	}

	return &Key{
		KeyType:               key.Kty,
		PublicKeyUse:          key.Use,
		KeyOperations:         key.KeyOps,
		Algorithm:             key.Alg,
		KeyID:                 key.Kid,
		X509URL:               key.X5u,
		X509CertificateChain:  certs,
		X509CertificateSHA1:   x5t,
		X509CertificateSHA256: x5tS256,
	}, nil
}

// ParseKey parses a JWK.
func ParseKey(data []byte) (*Key, error) {
	var key commonKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	return parseKey(&key)
}

func parseKey(key *commonKey) (*Key, error) {
	switch key.Kty {
	case jwa.EC:
		return parseEcdsaKey(key)
	case jwa.RSA:
		return parseRSAKey(key)
	case jwa.OKP:
		return parseOKPKey(key)
	case jwa.Oct:
		return parseSymmetricKey(key)
	default:
		return nil, fmt.Errorf("jwk: unknown key type: %q", key.Kty)
	}
}

// Set is a JWK Set.
type Set struct {
	Keys []*Key
}

// ParseSet parses a JWK Set.
func ParseSet(data []byte) (*Set, error) {
	var keys struct {
		Keys []commonKey `json:"keys"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}

	list := make([]*Key, 0, len(keys.Keys))
	for _, key := range keys.Keys {
		if key, err := parseKey(&key); err == nil {
			list = append(list, key)
			// Ignore keys that cannot be parsed.
		}
	}
	return &Set{
		Keys: list,
	}, nil
}

func (set *Set) Find(kid string) (key *Key, found bool) {
	for _, k := range set.Keys {
		if k.KeyID == kid {
			return k, true
		}
	}
	return nil, false
}
