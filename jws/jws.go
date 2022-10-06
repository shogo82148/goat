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
	Payload    string          `json:"payload"`
	Protected  string          `json:"protected"`
	Header     map[string]any  `json:"header"`
	Signature  string          `json:"signature"`
	Signatures []jsonSignature `json:"signatures"`
}

type jsonSignature struct {
	Protected string         `json:"protected"`
	Header    map[string]any `json:"header"`
	Signature string         `json:"signature"`
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

func NewHeader(alg jwa.SignatureAlgorithm) *Header {
	return &Header{
		alg: alg,
	}
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
	header, err := parseHeader(raw)
	if err != nil {
		return err
	}
	*h = *header
	return nil
}

// Message is signed message.
type Message struct {
	Signatures []*Signature

	// Base64 decoded payload.
	payload []byte
}

// Signature is a signature of Message.
type Signature struct {
	header    *Header // Unprotected Header
	protected *Header // Protected Header
	merged    *Header // merged header
	raw       []byte  // raw protected header
	signature []byte
}

func Parse(data []byte) (*Message, error) {
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
	header := data[:idx1]
	payload := data[idx1+1 : idx2]
	signature := data[idx2+1:]

	// pre-allocate buffer
	size := len(signature)
	if len(header) > size {
		size = len(header)
	}
	buf := make([]byte, b64.DecodedLen(size))

	// decode header
	n, err := b64.Decode(buf[:cap(buf)], header)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
	}
	buf = buf[:n]
	var h Header
	if err := h.UnmarshalJSON(buf); err != nil {
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
	}

	// decode payload
	payloadBytes := make([]byte, b64.DecodedLen(len(payload)))
	n, err = b64.Decode(payloadBytes, payload)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse payload: %w", err)
	}
	payloadBytes = payloadBytes[:n]

	// decode signature
	n, err = b64.Decode(buf[:cap(buf)], signature)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse signature: %w", err)
	}
	buf = buf[:n]

	return &Message{
		payload: payloadBytes,
		Signatures: []*Signature{
			{
				protected: &h,
				merged:    &h,
				raw:       append([]byte(nil), header...),
				signature: buf,
			},
		},
	}, nil
}

// ParseJSON parses a JSON Serialized JWS.
func ParseJSON(data []byte) (*Message, error) {
	var jws jsonJWS
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&jws); err != nil {
		return nil, fmt.Errorf("jws: failed to parse JWS: %w", err)
	}

	// decode payload
	payload, err := b64.DecodeString(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse payload: %w", err)
	}

	// decode signatures
	signatures := make([]*Signature, 0, len(jws.Signatures))
	for _, sig := range jws.Signatures {
		// decode protected header
		raw, err := b64.DecodeString(sig.Protected)
		if err != nil {
			return nil, fmt.Errorf("jws: failed to parse protected header: %w", err)
		}
		protected := new(Header)
		if err := protected.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("jws: failed to parse protected header: %w", err)
		}

		// decode unprotected header
		header, err := parseHeader(sig.Header)
		if err != nil {
			return nil, fmt.Errorf("jws: failed to parse unprotected header: %w", err)
		}

		merged, err := mergeHeader(protected.Raw, header.Raw)
		if err != nil {
			return nil, err
		}
		mergedHeader, err := parseHeader(merged)
		if err != nil {
			return nil, fmt.Errorf("jws: failed to parse header: %w", err)
		}

		// decode signature
		signature, err := b64.DecodeString(sig.Signature)
		if err != nil {
			return nil, fmt.Errorf("jws: failed to parse signature: %w", err)
		}

		signatures = append(signatures, &Signature{
			protected: protected,
			header:    header,
			merged:    mergedHeader,
			raw:       []byte(sig.Protected),
			signature: signature,
		})
	}

	return &Message{
		payload:    payload,
		Signatures: signatures,
	}, nil
}

func parseHeader(raw map[string]any) (*Header, error) {
	d := jsonutils.NewDecoder("jws", raw)
	h := &Header{
		Raw: raw,
	}

	if alg, ok := d.GetString("alg"); ok {
		h.alg = jwa.SignatureAlgorithm(alg)
	}

	if jku, ok := d.GetURL("jku"); ok {
		h.jku = jku
	}

	if v, ok := d.GetObject("jwk"); ok {
		key, err := jwk.ParseMap(v)
		if err != nil {
			d.SaveError(err)
		}
		h.jwk = key
	}

	if x5u, ok := d.GetURL("x5u"); ok {
		h.x5u = x5u
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
			}
			if cert0 == nil {
				cert0 = der
			}
			certs = append(certs, cert)
		}
		h.x5c = certs
	}

	if x5t, ok := d.GetBytes("x5t"); ok {
		h.x5t = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	if x5t256, ok := d.GetBytes("x5t#S256"); ok {
		h.x5tS256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	h.kid, _ = d.GetString("kid")
	h.typ, _ = d.GetString("typ")
	h.cty, _ = d.GetString("cty")
	h.crit, _ = d.GetStringArray("crit")

	if err := d.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func mergeHeader(a, b map[string]any) (map[string]any, error) {
	c := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		c[k] = v
	}
	for k, v := range b {
		if _, ok := c[k]; ok {
			return nil, errors.New("jws: duplicate header value")
		}
		c[k] = v
	}
	return c, nil
}

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	FindKey(header *Header) (key sig.Key, err error)
}

type FindKeyFunc func(header *Header) (key sig.Key, err error)

func (f FindKeyFunc) FindKey(header *Header) (key sig.Key, err error) {
	return f(header)
}

// Verify verifies the JWS message.
func (msg *Message) Verify(finder KeyFinder) (*Header, []byte, error) {
	// Base64-encoded payload
	payload := make([]byte, b64.EncodedLen(len(msg.payload)))
	b64.Encode(payload, msg.payload)

	// pre-allocate buffer
	size := 0
	for _, sig := range msg.Signatures {
		if len(sig.raw) > size {
			size = len(sig.raw)
		}
	}
	buf := make([]byte, len(payload)+size+1) // +1 for '.'

	for _, sig := range msg.Signatures {
		key, err := finder.FindKey(sig.merged)
		if err != nil {
			continue
		}
		buf = append(buf[:0], sig.raw...)
		buf = append(buf, '.')
		buf = append(buf, payload...)
		err = key.Verify(buf, sig.signature)
		if err == nil {
			return sig.protected, msg.payload, nil
		}
	}
	return nil, nil, errors.New("jws: failed to verify the message")
}

func Sign(header *Header, payload []byte, key sig.Key) ([]byte, error) {
	// encode the header
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// encode header and payload
	l1 := b64.EncodedLen(len(headerBytes))
	l2 := b64.EncodedLen(len(payload))
	buf := make([]byte, l1+l2+2+b64.EncodedLen(512))
	b64.Encode(buf[:l1:l1], headerBytes)
	buf[l1] = '.'
	b64.Encode(buf[l1+1:l1+1+l2:l1+1+l2], payload)

	// sign
	sig, err := key.Sign(buf[:l1+1+l2])
	if err != nil {
		return nil, err
	}

	// encode signature to base64
	l3 := b64.EncodedLen(len(sig))
	if len(buf) < l1+l2+l3+2 {
		tmp := make([]byte, l1+l2+l3+2)
		copy(tmp, buf)
		buf = tmp
	} else {
		buf = buf[:l1+l2+l3+2]
	}
	buf[l1+1+l2] = '.'
	b64.Encode(buf[l1+l2+2:], sig)
	return buf, nil
}

func encodeHeader(h *Header) ([]byte, error) {
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
			e.Set("jwk", json.RawMessage(data))
		}
	}

	if kid := h.kid; kid != "" {
		e.Set("kid", kid)
	}

	if x5u := h.x5u; x5u != nil {
		e.Set("x5u", x5u.String())
	}

	if x5c := h.x5c; x5c != nil {
		chain := make([][]byte, 0, len(x5c))
		for _, cert := range x5c {
			chain = append(chain, cert.Raw)
		}
		e.Set("x5c", chain)
	}
	if x5t := h.x5t; x5t != nil {
		e.SetBytes("x5t", x5t)
	} else if len(h.x5c) > 0 {
		cert := h.x5c[0]
		sum := sha1.Sum(cert.Raw)
		e.SetBytes("x5t", sum[:])
	}
	if x5t256 := h.x5tS256; x5t256 != nil {
		e.SetBytes("x5t#S256", x5t256)
	} else if len(h.x5c) > 0 {
		cert := h.x5c[0]
		sum := sha256.Sum256(cert.Raw)
		e.SetBytes("x5t#S256", sum[:])
	}

	if typ := h.typ; typ != "" {
		e.Set("typ", typ)
	}

	if cty := h.cty; cty != "" {
		e.Set("cty", cty)
	}

	if crit := h.crit; len(crit) > 0 {
		e.Set("crit", crit)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(e.Data())
}
