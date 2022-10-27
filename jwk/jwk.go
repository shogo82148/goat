// The package jwk handles JSON Web Key [RFC7517].
package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"reflect"

	"github.com/shogo82148/goat/ed448"
	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk/jwktypes"
	"github.com/shogo82148/goat/x25519"
	"github.com/shogo82148/goat/x448"
)

// Key is a JSON Web Key.
type Key struct {
	kty     jwa.KeyType
	use     jwktypes.KeyUse
	keyOps  []jwktypes.KeyOp
	alg     jwa.KeyAlgorithm
	kid     string
	x5u     *url.URL
	x5c     []*x509.Certificate
	x5t     []byte
	x5tS256 []byte
	priv    crypto.PrivateKey
	pub     crypto.PublicKey

	// Raw is the raw data of JSON-decoded JWK.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// KeyType is RFC7517 4.1. "kty" (Key Type) Parameter.
func (key *Key) KeyType() jwa.KeyType {
	return key.kty
}

// PublicKeyUse is RFC7517 4.2. "use" (Public Key Use) Parameter.
func (key *Key) PublicKeyUse() jwktypes.KeyUse {
	return key.use
}

func (key *Key) SetPublicKeyUse(use jwktypes.KeyUse) {
	key.use = use
}

// KeyOperations is RFC7517 4.3. "key_ops" (Key Operations) Parameter.
func (key *Key) KeyOperations() []jwktypes.KeyOp {
	return key.keyOps
}

func (key *Key) SetKeyOperation(keyOps []jwktypes.KeyOp) {
	key.keyOps = keyOps
}

// Algorithm is RFC7517 4.4. "alg" (Algorithm) Parameter.
func (key *Key) Algorithm() jwa.KeyAlgorithm {
	return key.alg
}

func (key *Key) SetAlgorithm(alg jwa.KeyAlgorithm) {
	key.alg = alg
}

// KeyID is RFC7517 4.5. "kid" (Key ID) Parameter.
func (key *Key) KeyID() string {
	return key.kid
}

func (key *Key) SetKeyID(kid string) {
	key.kid = kid
}

// X509URL is RFC7517 4.6. "x5u" (X.509 URL) Parameter.
func (key *Key) X509URL() *url.URL {
	return key.x5u
}

func (key *Key) SetX509URL(x5u *url.URL) {
	key.x5u = x5u
}

// X509CertificateChain is RFC7517 4.7. "x5c" (X.509 Certificate Chain) Parameter.
func (key *Key) X509CertificateChain() []*x509.Certificate {
	return key.x5c
}

func (key *Key) SetX509CertificateChain(x5c []*x509.Certificate) {
	key.x5c = x5c
}

// X509CertificateSHA1 is RFC7517 4.8. "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter.
func (key *Key) X509CertificateSHA1() []byte {
	return key.x5t
}

func (key *Key) SetX509CertificateSHA1(x5t []byte) {
	key.x5t = x5t
}

// X509CertificateSHA256 is RFC7517 4.9. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter.
func (key *Key) X509CertificateSHA256() []byte {
	return key.x5tS256
}

func (key *Key) SetX509CertificateSHA256(x5tS256 []byte) {
	key.x5tS256 = x5tS256
}

func NewPrivateKey(key crypto.PrivateKey) (*Key, error) {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		if err := validateEcdsaPrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.EC,
			priv: key,
			pub:  key.Public(),
		}, nil
	case *rsa.PrivateKey:
		if err := validateRSAPrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.RSA,
			priv: key,
			pub:  key.Public(),
		}, nil
	case ed25519.PrivateKey:
		if err := validateEd25519PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case x25519.PrivateKey:
		if err := validateX25519PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case ed448.PrivateKey:
		if err := validateEd448PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case x448.PrivateKey:
		if err := validateX448PrivateKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty:  jwa.OKP,
			priv: key,
			pub:  key.Public(),
		}, nil
	case []byte:
		return &Key{
			kty:  jwa.Oct,
			priv: append([]byte(nil), key...),
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown private key type: %T", key)
	}
}

func NewPublicKey(key crypto.PublicKey) (*Key, error) {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		if err := validateEcdsaPublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.EC,
			pub: key,
		}, nil
	case *rsa.PublicKey:
		if err := validateRSAPublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.RSA,
			pub: key,
		}, nil
	case ed25519.PublicKey:
		if err := validateEd25519PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case x25519.PublicKey:
		if err := validateX25519PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case ed448.PublicKey:
		if err := validateEd448PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	case x448.PublicKey:
		if err := validateX448PublicKey(key); err != nil {
			return nil, err
		}
		return &Key{
			kty: jwa.OKP,
			pub: key,
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unknown public key type: %T", key)
	}
}

// decode common parameters such as certificate and thumbprints, etc.
func decodeCommonParameters(d *jsonutils.Decoder, key *Key) {
	key.kty = jwa.KeyType(d.MustString("kty"))
	key.kid, _ = d.GetString("kid")
	if use, ok := d.GetString("use"); ok {
		key.use = jwktypes.KeyUse(use)
	}
	if ops, ok := d.GetStringArray("key_ops"); ok {
		key.keyOps = make([]jwktypes.KeyOp, len(ops))
		for i := range ops {
			key.keyOps[i] = jwktypes.KeyOp(ops[i])
		}
	}
	if alg, ok := d.GetString("alg"); ok {
		key.alg = jwa.KeyAlgorithm(alg)
	}

	// decode the certificates
	if x5u, ok := d.GetURL("x5u"); ok {
		key.x5u = x5u
	}
	var cert0 []byte
	if x5c, ok := d.GetStringArray("x5c"); ok {
		var certs []*x509.Certificate
		for i, s := range x5c {
			der, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				d.SaveError(fmt.Errorf("jwk: failed to parse the parameter x5c[%d]: %w", i, err))
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				d.SaveError(fmt.Errorf("jwk: failed to parse certificate: %w", err))
				return
			}
			if cert0 == nil {
				cert0 = der
			}
			certs = append(certs, cert)
		}
		key.x5c = certs
	}

	// check thumbprints
	if x5t, ok := d.GetBytes("x5t"); ok {
		key.x5t = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}
	if x5t256, ok := d.GetBytes("x5t#S256"); ok {
		key.x5tS256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwk: sha-256 thumbprint of certificate is mismatch"))
			}
		}
	}
}

func encodeCommonParameters(e *jsonutils.Encoder, key *Key) {
	e.Set("kty", key.kty.String())
	if v := key.kid; v != "" {
		e.Set("kid", v)
	}
	if v := key.use; v != "" {
		e.Set("use", v)
	}
	if v := key.keyOps; v != nil {
		e.Set("key_ops", v)
	}
	if v := key.alg; v != "" {
		e.Set("alg", v)
	}
	if x5u := key.x5u; x5u != nil {
		e.Set("x5u", x5u.String())
	}
	if x5c := key.x5c; x5c != nil {
		chain := make([][]byte, 0, len(x5c))
		for _, cert := range x5c {
			chain = append(chain, cert.Raw)
		}
		e.Set("x5c", chain)
	}
	if x5t := key.x5t; x5t != nil {
		e.SetBytes("x5t", x5t)
	} else if len(key.x5c) > 0 {
		cert := key.x5c[0]
		sum := sha1.Sum(cert.Raw)
		e.SetBytes("x5t", sum[:])
	}
	if x5t256 := key.x5tS256; x5t256 != nil {
		e.SetBytes("x5t#S256", x5t256)
	} else if len(key.x5c) > 0 {
		cert := key.x5c[0]
		sum := sha256.Sum256(cert.Raw)
		e.SetBytes("x5t#S256", sum[:])
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
	return ParseMap(raw)
}

var _ json.Unmarshaler = (*Key)(nil)

// UnmarshalJSON implements [encoding/json.Unmarshaler]
func (key *Key) UnmarshalJSON(data []byte) error {
	k, err := ParseKey(data)
	if err != nil {
		return err
	}
	*key = *k
	return nil
}

var _ json.Marshaler = (*Key)(nil)

// MarshalJSON implements [encoding/json.Marshaler]
func (key *Key) MarshalJSON() ([]byte, error) {
	raw := make(map[string]any, len(key.Raw))
	for k, v := range key.Raw {
		raw[k] = v
	}
	e := jsonutils.NewEncoder(raw)
	encodeCommonParameters(e, key)
	if err := e.Err(); err != nil {
		return nil, err
	}

	switch priv := key.priv.(type) {
	case *ecdsa.PrivateKey:
		pub, ok := key.pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for ecdsa: %T", key.pub)
		}
		encodeEcdsaKey(e, priv, pub)
	case *rsa.PrivateKey:
		pub, ok := key.pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for rsa: %T", key.pub)
		}
		encodeRSAKey(e, priv, pub)
	case ed25519.PrivateKey:
		pub, ok := key.pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for ed25519: %T", key.pub)
		}
		encodeEd25519Key(e, priv, pub)
	case x25519.PrivateKey:
		pub, ok := key.pub.(x25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for x25519: %T", key.pub)
		}
		encodeX25519Key(e, priv, pub)
	case ed448.PrivateKey:
		pub, ok := key.pub.(ed448.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for ed448: %T", key.pub)
		}
		encodeEd448Key(e, priv, pub)
	case x448.PrivateKey:
		pub, ok := key.pub.(x448.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwk: public key type is mismatch for x448: %T", key.pub)
		}
		encodeX448Key(e, priv, pub)
	case []byte:
		if key.pub != nil {
			return nil, errors.New("jwk: public key is allowed for symmetric keys")
		}
		encodeSymmetricKey(e, priv)
	case nil:
		// the key has only public key.
		switch pub := key.pub.(type) {
		case *ecdsa.PublicKey:
			encodeEcdsaKey(e, nil, pub)
		case *rsa.PublicKey:
			encodeRSAKey(e, nil, pub)
		case ed25519.PublicKey:
			encodeEd25519Key(e, nil, pub)
		case x25519.PublicKey:
			encodeX25519Key(e, nil, pub)
		case ed448.PublicKey:
			encodeEd448Key(e, nil, pub)
		case x448.PublicKey:
			encodeX448Key(e, nil, pub)
		default:
			return nil, newUnknownKeyTypeError(key)
		}
	default:
		return nil, newUnknownKeyTypeError(key)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(e.Data())
}

// Thumbprint computes the thumbprint of the key defined in RFC 7638.
func (key *Key) Thumbprint(h hash.Hash) ([]byte, error) {
	// remove optional parameters
	thumbKey := &Key{
		kty: key.kty,
		pub: key.pub,
	}
	data, err := thumbKey.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// PrivateKey returns the private key.
// If the key doesn't contain any private key, it returns nil.
func (key *Key) PrivateKey() crypto.PrivateKey {
	return key.priv
}

// SetPrivateKey sets the private key.
// If priv has Public() method, it sets the public key as well.
func (key *Key) SetPrivateKey(priv crypto.PrivateKey) {
	key.priv = priv
	if pub, ok := priv.(interface{ Public() crypto.PublicKey }); ok {
		key.pub = pub.Public()
	} else {
		key.pub = nil
	}
}

// PublicKey returns the public key.
// If the key doesn't contain any public key, it returns nil.
func (key *Key) PublicKey() crypto.PublicKey {
	return key.pub
}

// SetPublicKey sets the public key, and removes the private key.
func (key *Key) SetPublicKey(pub crypto.PublicKey) {
	key.priv = nil
	key.pub = pub
}

// ParseMap parses a JWK that is decoded by the json package.
func ParseMap(raw map[string]any) (*Key, error) {
	d := jsonutils.NewDecoder("jwk", raw)
	key := &Key{
		Raw: raw,
	}
	decodeCommonParameters(d, key)
	if err := d.Err(); err != nil {
		return nil, err
	}

	switch key.kty {
	case jwa.EC:
		parseEcdsaKey(d, key)
	case jwa.RSA:
		parseRSAKey(d, key)
	case jwa.OKP:
		parseOKPKey(d, key)
	case jwa.Oct:
		parseSymmetricKey(d, key)
	default:
		return nil, fmt.Errorf("jwk: unknown key type: %q", key.kty)
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
		if key, err := ParseMap(key); err == nil {
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

// Find finds the key that has kid.
func (set *Set) Find(kid string) (key *Key, found bool) {
	for _, k := range set.Keys {
		if k.kid == kid {
			return k, true
		}
	}
	return nil, false
}

var _ json.Unmarshaler = (*Set)(nil)

// UnmarshalJSON implements [encoding/json.Unmarshaler]
func (set *Set) UnmarshalJSON(data []byte) error {
	s, err := ParseSet(data)
	if err != nil {
		return err
	}
	*set = *s
	return nil
}

var _ json.Marshaler = (*Set)(nil)

// MarshalJSON implements [encoding/json.Marshaler]
func (set *Set) MarshalJSON() ([]byte, error) {
	return nil, nil
}

type unknownKeyTypeError struct {
	pub  reflect.Type
	priv reflect.Type
}

func newUnknownKeyTypeError(key *Key) *unknownKeyTypeError {
	return &unknownKeyTypeError{
		pub:  reflect.TypeOf(key.PublicKey()),
		priv: reflect.TypeOf(key.PrivateKey()),
	}
}

func (err *unknownKeyTypeError) Error() string {
	return "jwk: unknown private and public key type: " + err.priv.String() + ", " + err.pub.String()
}
