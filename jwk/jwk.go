// The package jwk handles JSON Web Key [RFC7517].
package jwk

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/shogo82148/goat/internal/jsonutils"
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
	X509URL *url.URL

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

	// Raw is the raw data of JWK.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// decode common parameters such as certificate and thumbprints, etc.
func decodeCommonParameters(d *jsonutils.Decoder, key *Key) {
	key.KeyType = jwa.KeyType(d.MustString("kty"))
	key.KeyID, _ = d.GetString("kid")
	key.PublicKeyUse, _ = d.GetString("use")
	if ops, ok := d.GetStringArray("key_ops"); ok {
		key.KeyOperations = ops
	}
	if alg, ok := d.GetString("alg"); ok {
		key.Algorithm = jwa.KeyAlgorithm(alg)
	}

	// decode the certificates
	if x5u, ok := d.GetURL("x5u"); ok {
		key.X509URL = x5u
	}
	var cert0 []byte
	if x5c, ok := d.GetStringArray("x5c"); ok {
		var certs []*x509.Certificate
		for i, s := range x5c {
			der := d.DecodeStd(s, "x5c["+strconv.Itoa(i)+"]")
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				d.NewError(fmt.Errorf("jwk: failed to parse certificate: %w", err))
				return
			}
			if cert0 == nil {
				cert0 = der
			}
			certs = append(certs, cert)
		}
		key.X509CertificateChain = certs
	}

	// check thumbprints
	if x5t, ok := d.GetBytes("x5t"); ok {
		key.X509CertificateSHA1 = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.NewError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}
	if x5t256, ok := d.GetBytes("x5t#S256"); ok {
		key.X509CertificateSHA256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.NewError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}
}

// ParseKey parses a JWK.
func ParseKey(data []byte) (*Key, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return parseKey(raw)
}

func parseKey(raw map[string]any) (*Key, error) {
	d := jsonutils.NewDecoder("jwk", raw)
	key := &Key{
		Raw: raw,
	}
	decodeCommonParameters(d, key)
	if err := d.Err(); err != nil {
		return nil, err
	}

	switch key.KeyType {
	case jwa.EC:
		parseEcdsaKey(d, key)
	case jwa.RSA:
		parseRSAKey(d, key)
	case jwa.OKP:
		parseOKPKey(d, key)
	case jwa.Oct:
		parseSymmetricKey(d, key)
	default:
		return nil, fmt.Errorf("jwk: unknown key type: %q", key.KeyType)
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	return key, nil
}

// Set is a JWK Set.
type Set struct {
	Keys []*Key
}

// ParseSet parses a JWK Set.
func ParseSet(data []byte) (*Set, error) {
	var keys struct {
		Keys []map[string]any `json:"keys"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&keys); err != nil {
		return nil, err
	}

	list := make([]*Key, 0, len(keys.Keys))
	for _, key := range keys.Keys {
		if key, err := parseKey(key); err == nil {
			list = append(list, key)

			// from: RFC7517 Section 5. JWK Set Format
			// Implementations SHOULD ignore JWKs within a JWK Set that use "kty"
			// (key type) values that are not understood by them, that are missing
			// required members, or for which values are out of the supported
			// ranges.
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
