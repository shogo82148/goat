// Package jws handles JSON Web Signatures in [RFC7515].
package jws

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

var b64 = base64.RawURLEncoding

type jsonJWS struct {
	Payload    *string         `json:"payload"`
	Protected  *string         `json:"protected,omitempty"`
	Header     map[string]any  `json:"header,omitempty"`
	Signature  *string         `json:"signature,omitempty"`
	Signatures []jsonSignature `json:"signatures,omitempty"`
}

type jsonSignature struct {
	Protected *string        `json:"protected,omitempty"`
	Header    map[string]any `json:"header,omitempty"`
	Signature *string        `json:"signature"`
}

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	alg     jwa.SignatureAlgorithm
	jku     *url.URL
	jwk     *jwk.Key
	kid     string
	x5u     *url.URL
	x5c     []*x509.Certificate
	x5t     []byte
	x5tS256 []byte
	typ     string
	cty     string
	crit    []string

	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// Algorithm is RFC7515 Section 4.1.1. "alg" (Algorithm) Header Parameter.
func (h *Header) Algorithm() jwa.SignatureAlgorithm {
	return h.alg
}

func (h *Header) SetAlgorithm(alg jwa.SignatureAlgorithm) {
	h.alg = alg
}

// JWKSetURL is RFC7515 Section 4.1.2. "jku" (JWK Set URL) Header Parameter.
func (h *Header) JWKSetURL() *url.URL {
	return h.jku
}

func (h *Header) SetJWKSetURL(jku *url.URL) {
	h.jku = jku
}

// JWK is RFC7515 Section 4.1.3. "jwk" (JSON Web Key) Header Parameter.
func (h *Header) JWK() *jwk.Key {
	return h.jwk
}

func (h *Header) SetJWK(jwk *jwk.Key) {
	h.jwk = jwk
}

// KeyID is RFC7515 Section 4.1.4. "kid" (Key ID) Header Parameter.
func (h *Header) KeyID() string {
	return h.kid
}

func (h *Header) SetKeyID(kid string) {
	h.kid = kid
}

// X509URL is RFC7515 Section 4.1.5. "x5u" (X.509 URL) Header Parameter.
func (h *Header) X509URL() *url.URL {
	return h.x5u
}

func (h *Header) SetX509URL(x5u *url.URL) {
	h.x5u = x5u
}

// X509CertificateChain is RFC7515 Section 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter.
func (h *Header) X509CertificateChain() []*x509.Certificate {
	return h.x5c
}

func (h *Header) SetX509CertificateChain(x5c []*x509.Certificate) {
	h.x5c = x5c
}

// X509CertificateSHA1 is RFC7515 Section 4.1.7. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA1() []byte {
	return h.x5t
}

func (h *Header) SetX509CertificateSHA1(x5t []byte) {
	h.x5t = x5t
}

// X509CertificateSHA256 is RFC7517 Section 4.1.8. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA256() []byte {
	return h.x5tS256
}

func (h *Header) SetX509CertificateSHA256(x5tS256 []byte) {
	h.x5tS256 = x5tS256
}

// Type is RFC7517 Section 4.1.9. "typ" (Type) Header Parameter.
func (h *Header) Type() string {
	return h.typ
}

func (h *Header) SetType(typ string) {
	h.typ = typ
}

// ContentType is RFC7517 Section 4.1.10. "cty" (Content Type) Header Parameter.
func (h *Header) ContentType() string {
	return h.cty
}

func (h *Header) SetContentType(cty string) {
	h.cty = cty
}

// Critical is 4.1.11. "crit" (Critical) Header Parameter.
func (h *Header) Critical() []string {
	return h.crit
}

func (h *Header) SetCritical(crit []string) {
	h.crit = crit
}

func (h *Header) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	header, err := decodeHeader(raw)
	if err != nil {
		return err
	}
	*h = *header
	return nil
}

func (h *Header) MarshalJSON() ([]byte, error) {
	raw, err := encodeHeader(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(raw)
}

// NewMessage returns a new Message that has no signature.
func NewMessage(payload []byte) *Message {
	return &Message{
		b64payload: b64Encode(payload),
		payload:    append([]byte(nil), payload...),
	}
}

// Message is signed message.
type Message struct {
	Signatures []*Signature

	b64payload []byte
	payload    []byte
}

// Signature is a signature of Message.
type Signature struct {
	header       *Header // Unprotected Header
	protected    *Header // Protected Header
	raw          []byte  // protected header
	b64signature []byte
	signature    []byte
}

func Parse(data []byte) (*Message, error) {
	// copy data
	data = append([]byte(nil), data...)

	// split to segments
	idx1 := bytes.IndexByte(data, '.')
	if idx1 < 0 {
		return nil, errors.New("jws: failed to parse JWS: invalid format")
	}
	idx2 := bytes.IndexByte(data[idx1+1:], '.')
	if idx2 < 0 {
		return nil, errors.New("jws: failed to parse JWS: invalid format")
	}
	idx2 += idx1 + 1
	b64header := data[:idx1]
	b64payload := data[idx1+1 : idx2]
	b64signature := data[idx2+1:]

	// decode header
	header, err := b64Decode(b64header)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
	}
	var h Header
	if err := h.UnmarshalJSON(header); err != nil {
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
	}

	// decode payload
	payload, err := b64Decode(b64payload)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse payload: %w", err)
	}

	// decode signature
	signature, err := b64Decode(b64signature)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse signature: %w", err)
	}

	return &Message{
		b64payload: b64payload,
		payload:    payload,
		Signatures: []*Signature{
			{
				protected:    &h,
				raw:          b64header,
				b64signature: b64signature,
				signature:    signature,
			},
		},
	}, nil
}

// UnmarshalJSON implements [encoding/json.Unmarshaler].
// It parses data as JSON Serialized JWS.
func (msg *Message) UnmarshalJSON(data []byte) error {
	var jws jsonJWS
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&jws); err != nil {
		return fmt.Errorf("jws: failed to parse JWS: %w", err)
	}

	// decode payload
	if jws.Payload == nil {
		return errors.New("jws: failed to parse JWS: payload is missing")
	}
	payload, err := b64.DecodeString(*jws.Payload)
	if err != nil {
		return fmt.Errorf("jws: failed to parse payload: %w", err)
	}

	hasSigs := jws.Signatures != nil
	flattened := jws.Signature != nil

	if hasSigs && flattened {
		return errors.New("jws: failed to parse JWS: both signatures and signature are set")
	}
	if !hasSigs && !flattened {
		return errors.New("jws: failed to parse JWS: neither signatures nor signature are set")
	}

	sigs := jws.Signatures
	if flattened {
		sigs = []jsonSignature{
			{
				Protected: jws.Protected,
				Header:    jws.Header,
				Signature: jws.Signature,
			},
		}
	}

	// decode signatures
	signatures := make([]*Signature, 0, len(jws.Signatures))
	for _, sig := range sigs {
		// decode protected header
		var protected *Header
		if sig.Protected != nil {
			raw, err := b64.DecodeString(*sig.Protected)
			if err != nil {
				return fmt.Errorf("jws: failed to parse protected header: %w", err)
			}
			protected = new(Header)
			if err := protected.UnmarshalJSON(raw); err != nil {
				return fmt.Errorf("jws: failed to parse protected header: %w", err)
			}
		}

		// decode unprotected header
		var header *Header
		if sig.Header != nil {
			header, err = decodeHeader(sig.Header)
			if err != nil {
				return fmt.Errorf("jws: failed to parse unprotected header: %w", err)
			}
		}
		if protected == nil && header == nil {
			return errors.New("jws: failed to parse JWS: both protected and unprotected header are missing")
		}

		// decode signature
		if sig.Signature == nil {
			return errors.New("jws: failed to parse signature: signature is missing")
		}
		signature, err := b64.DecodeString(*sig.Signature)
		if err != nil {
			return fmt.Errorf("jws: failed to parse signature: %w", err)
		}

		signatures = append(signatures, &Signature{
			protected:    protected,
			header:       header,
			raw:          []byte(*sig.Protected),
			b64signature: []byte(*sig.Signature),
			signature:    signature,
		})
	}

	*msg = Message{
		b64payload: []byte(*jws.Payload),
		payload:    payload,
		Signatures: signatures,
	}
	return nil
}

func decodeHeader(raw map[string]any) (*Header, error) {
	d := jsonutils.NewDecoder("jws", raw)
	h := &Header{
		Raw: raw,
	}

	if alg, ok := d.GetString(jwa.AlgorithmKey); ok {
		h.alg = jwa.SignatureAlgorithm(alg)
	}

	if jku, ok := d.GetURL(jwa.JWKSetURLKey); ok {
		h.jku = jku
	}

	if v, ok := d.GetObject(jwa.JSONWebKey); ok {
		key, err := jwk.ParseMap(v)
		if err != nil {
			d.SaveError(err)
		}
		h.jwk = key
	}

	if x5u, ok := d.GetURL(jwa.X509URLKey); ok {
		h.x5u = x5u
	}

	var cert0 []byte
	if x5c, ok := d.GetStringArray(jwa.X509CertificateChainKey); ok {
		var certs []*x509.Certificate
		for i, s := range x5c {
			der, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				d.SaveError(fmt.Errorf("jwk: failed to parse the parameter x5c[%d]: %w", i, err))
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				d.SaveError(fmt.Errorf("jwk: failed to parse certificate: %w", err))
			}
			if cert0 == nil {
				cert0 = der
			}
			certs = append(certs, cert)
		}
		h.x5c = certs
	}

	if x5t, ok := d.GetBytes(jwa.X509CertificateSHA1Thumbprint); ok {
		h.x5t = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	if x5t256, ok := d.GetBytes(jwa.X509CertificateSHA256Thumbprint); ok {
		h.x5tS256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwk: sha-256 thumbprint of certificate is mismatch"))
			}
		}
	}

	h.kid, _ = d.GetString(jwa.KeyIDKey)
	h.typ, _ = d.GetString(jwa.TypeKey)
	h.cty, _ = d.GetString(jwa.ContentTypeKey)
	h.crit, _ = d.GetStringArray(jwa.CriticalKey)

	if err := d.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func encodeHeader(h *Header) (map[string]any, error) {
	if h == nil {
		return nil, nil
	}
	raw := make(map[string]any, len(h.Raw))
	for k, v := range h.Raw {
		raw[k] = v
	}
	e := jsonutils.NewEncoder(raw)
	if v := h.alg; v != "" {
		e.Set(jwa.AlgorithmKey, string(v))
	}

	if u := h.jku; u != nil {
		e.Set(jwa.JWKSetURLKey, u.String())
	}

	if key := h.jwk; key != nil {
		data, err := key.MarshalJSON()
		if err != nil {
			e.SaveError(err)
		} else {
			e.Set(jwa.JSONWebKey, json.RawMessage(data))
		}
	}

	if kid := h.kid; kid != "" {
		e.Set(jwa.KeyIDKey, kid)
	}

	if x5u := h.x5u; x5u != nil {
		e.Set(jwa.X509URLKey, x5u.String())
	}

	if x5c := h.x5c; x5c != nil {
		chain := make([][]byte, 0, len(x5c))
		for _, cert := range x5c {
			chain = append(chain, cert.Raw)
		}
		e.Set(jwa.X509CertificateChainKey, chain)
	}
	if x5t := h.x5t; x5t != nil {
		e.SetBytes(jwa.X509CertificateSHA1Thumbprint, x5t)
	} else if len(h.x5c) > 0 {
		cert := h.x5c[0]
		sum := sha1.Sum(cert.Raw)
		e.SetBytes(jwa.X509CertificateSHA1Thumbprint, sum[:])
	}
	if x5t256 := h.x5tS256; x5t256 != nil {
		e.SetBytes(jwa.X509CertificateSHA256Thumbprint, x5t256)
	} else if len(h.x5c) > 0 {
		cert := h.x5c[0]
		sum := sha256.Sum256(cert.Raw)
		e.SetBytes(jwa.X509CertificateSHA256Thumbprint, sum[:])
	}

	if typ := h.typ; typ != "" {
		e.Set(jwa.TypeKey, typ)
	}

	if cty := h.cty; cty != "" {
		e.Set(jwa.ContentTypeKey, cty)
	}

	if crit := h.crit; len(crit) > 0 {
		e.Set(jwa.CriticalKey, crit)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return e.Data(), nil
}

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	FindKey(protected, unprotected *Header) (key sig.SigningKey, err error)
}

type FindKeyFunc func(protected, unprotected *Header) (key sig.SigningKey, err error)

func (f FindKeyFunc) FindKey(protected, unprotected *Header) (key sig.SigningKey, err error) {
	return f(protected, unprotected)
}

// Verify verifies the JWS message.
func (msg *Message) Verify(finder KeyFinder) (*Header, []byte, error) {
	// pre-allocate buffer
	size := 0
	for _, sig := range msg.Signatures {
		if len(sig.raw) > size {
			size = len(sig.raw)
		}
	}
	size += len(msg.payload) + 1 // +1 for '.'
	buf := make([]byte, size)

	for _, sig := range msg.Signatures {
		key, err := finder.FindKey(sig.protected, sig.header)
		if err != nil {
			continue
		}
		buf = buf[:0]
		buf = append(buf, sig.raw...)
		buf = append(buf, '.')
		buf = append(buf, msg.b64payload...)
		err = key.Verify(buf, sig.signature)
		if err == nil {
			return sig.protected, msg.payload, nil
		}
	}
	return nil, nil, errors.New("jws: failed to verify the message")
}

func (msg *Message) Sign(protected, header *Header, key sig.SigningKey) error {
	// encode the header
	h1, err := encodeHeader(protected)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(h1)
	if err != nil {
		return err
	}
	raw = b64Encode(raw)

	// sign
	buf := make([]byte, 0, len(msg.b64payload)+len(raw)+1)
	buf = append(buf, raw...)
	buf = append(buf, '.')
	buf = append(buf, msg.b64payload...)
	signature, err := key.Sign(buf)
	if err != nil {
		return fmt.Errorf("jws: failed to sign: %w", err)
	}

	msg.Signatures = append(msg.Signatures, &Signature{
		protected:    protected,
		header:       header,
		raw:          raw,
		b64signature: b64Encode(signature),
		signature:    signature,
	})
	return nil
}

func (msg *Message) Compact() ([]byte, error) {
	if len(msg.Signatures) != 1 {
		return nil, fmt.Errorf("jws: invalid number of signatures: %d", len(msg.Signatures))
	}
	sig := msg.Signatures[0]

	buf := make([]byte, 0, len(sig.raw)+len(msg.b64payload)+len(sig.b64signature)+2)
	buf = append(buf, sig.raw...)
	buf = append(buf, '.')
	buf = append(buf, msg.b64payload...)
	buf = append(buf, '.')
	buf = append(buf, sig.b64signature...)
	return buf, nil
}

func b64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, b64.DecodedLen(len(src)))
	n, err := b64.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func b64Encode(src []byte) []byte {
	dst := make([]byte, b64.EncodedLen(len(src)))
	b64.Encode(dst, src)
	return dst
}
