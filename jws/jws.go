// Package jws handles JSON Web Signatures defined in RFC 7515.
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
	"sort"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

// shorthand for base64.RawURLEncoding
var b64 = base64.RawURLEncoding

var knownParams = [...]string{
	jwa.AlgorithmKey,
	jwa.JWKSetURLKey,
	jwa.JSONWebKey,
	jwa.KeyIDKey,
	jwa.X509URLKey,
	jwa.X509CertificateChainKey,
	jwa.X509CertificateSHA1Thumbprint,
	jwa.X509CertificateSHA256Thumbprint,
	jwa.TypeKey,
	jwa.CriticalKey,
	jwa.Base64URLEncodePayloadKey,
}

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any

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
	nb64    bool // nb64 is !b64
}

// NewHeader returns a new Header.
func NewHeader() *Header {
	return &Header{
		Raw: map[string]any{},
	}
}

// Algorithm is RFC 7515 Section 4.1.1. "alg" (Algorithm) Header Parameter.
func (h *Header) Algorithm() jwa.SignatureAlgorithm {
	return h.alg
}

// SetAlgorithm sets RFC 7515 Section 4.1.1. "alg" (Algorithm) Header Parameter.
func (h *Header) SetAlgorithm(alg jwa.SignatureAlgorithm) {
	h.alg = alg
}

// JWKSetURL is RFC 7515 Section 4.1.2. "jku" (JWK Set URL) Header Parameter.
func (h *Header) JWKSetURL() *url.URL {
	return h.jku
}

// SetJWKSetURL sets RFC 7515 Section 4.1.2. "jku" (JWK Set URL) Header Parameter.
func (h *Header) SetJWKSetURL(jku *url.URL) {
	h.jku = jku
}

// JWK is RFC 7515 Section 4.1.3. "jwk" (JSON Web Key) Header Parameter.
func (h *Header) JWK() *jwk.Key {
	return h.jwk
}

// SetJWK sets RFC 7515 Section 4.1.3. "jwk" (JSON Web Key) Header Parameter.
func (h *Header) SetJWK(jwk *jwk.Key) {
	h.jwk = jwk
}

// KeyID is RFC 7515 Section 4.1.4. "kid" (Key ID) Header Parameter.
func (h *Header) KeyID() string {
	return h.kid
}

// SetKeyID sets RFC 7515 Section 4.1.4. "kid" (Key ID) Header Parameter.
func (h *Header) SetKeyID(kid string) {
	h.kid = kid
}

// X509URL is RFC 7515 Section 4.1.5. "x5u" (X.509 URL) Header Parameter.
func (h *Header) X509URL() *url.URL {
	return h.x5u
}

// SetX509URL sets RFC 7515 Section 4.1.5. "x5u" (X.509 URL) Header Parameter.
func (h *Header) SetX509URL(x5u *url.URL) {
	h.x5u = x5u
}

// X509CertificateChain is RFC 7515 Section 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter.
func (h *Header) X509CertificateChain() []*x509.Certificate {
	return h.x5c
}

// SetX509CertificateChain sets RFC 7515 Section 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter.
func (h *Header) SetX509CertificateChain(x5c []*x509.Certificate) {
	h.x5c = x5c
}

// X509CertificateSHA1 is RFC 7515 Section 4.1.7. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA1() []byte {
	return h.x5t
}

// SetX509CertificateSHA1 sets RFC 7515 Section 4.1.7. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
func (h *Header) SetX509CertificateSHA1(x5t []byte) {
	h.x5t = x5t
}

// X509CertificateSHA256 is RFC 7517 Section 4.1.8. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA256() []byte {
	return h.x5tS256
}

// SetX509CertificateSHA256 sets RFC 7517 Section 4.1.8. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
func (h *Header) SetX509CertificateSHA256(x5tS256 []byte) {
	h.x5tS256 = x5tS256
}

// Type is RFC 7517 Section 4.1.9. "typ" (Type) Header Parameter.
func (h *Header) Type() string {
	return h.typ
}

// SetType sets RFC 7517 Section 4.1.9. "typ" (Type) Header Parameter.
func (h *Header) SetType(typ string) {
	h.typ = typ
}

// ContentType is RFC 7517 Section 4.1.10. "cty" (Content Type) Header Parameter.
func (h *Header) ContentType() string {
	return h.cty
}

// SetContentType sets RFC 7517 Section 4.1.10. "cty" (Content Type) Header Parameter.
func (h *Header) SetContentType(cty string) {
	h.cty = cty
}

// Critical gets RFC 7515 Section 4.1.11. "crit" (Critical) Header Parameter.
func (h *Header) Critical() []string {
	return h.crit
}

// SetCritical sets RFC 7515 Section 4.1.11. "crit" (Critical) Header Parameter.
func (h *Header) SetCritical(crit []string) {
	h.crit = make([]string, 0, len(crit))
LOOP:
	for _, param1 := range crit {
		for _, param2 := range h.crit {
			if param1 == param2 {
				continue LOOP
			}
		}
		h.crit = append(h.crit, param1)
	}
	sort.Strings(h.crit)
}

// Base64 gets RFC 7797 Section 3. The "b64" Header Parameter.
func (h *Header) Base64() bool {
	return !h.nb64
}

// SetBase64 sets RFC 7797 Section 3. The "b64" Header Parameter.
// If b64 is false, it adds "b64" into "crit" (Critical) Header Parameter.
func (h *Header) SetBase64(b64 bool) {
	h.nb64 = !b64
	if !b64 {
		for _, param := range h.crit {
			if param == "b64" {
				return // "b64" is already contained.
			}
		}
		h.crit = append(h.crit, "b64")
	}
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
		payload: b64Encode(payload),
		nb64:    false,
	}
}

// NewRawMessage returns a new Message that has no signature.
func NewRawMessage(payload []byte) *Message {
	return &Message{
		payload: append([]byte(nil), payload...),
		nb64:    true,
	}
}

// Message is signed message.
type Message struct {
	Signatures []*Signature

	payload []byte
	nb64    bool // nb64 is !b64
}

// Signature is a signature of Message.
type Signature struct {
	header       *Header // Unprotected Header
	protected    *Header // Protected Header
	rawProtected []byte  // protected header
	b64signature []byte
	signature    []byte
}

// ParseCompact parses a Compact Serialized JWS Signature.
func ParseCompact(data []byte) (*Message, error) {
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
	payload := data[idx1+1 : idx2]
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

	// decode signature
	signature, err := b64Decode(b64signature)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse signature: %w", err)
	}

	return &Message{
		payload: payload,
		nb64:    h.nb64,
		Signatures: []*Signature{
			{
				protected:    &h,
				rawProtected: b64header,
				b64signature: b64signature,
				signature:    signature,
			},
		},
	}, nil
}

func Parse(data []byte) (*Message, error) {
	var msg Message
	if err := msg.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &msg, nil
}

// UnmarshalJSON implements [encoding/json.Unmarshaler].
// It parses data as JSON Serialized JWS.
func (msg *Message) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("jws: failed to parse JWS: %w", err)
	}

	var m Message

	// decode payload
	if payloadAny, ok := raw["payload"]; ok {
		payload, ok := payloadAny.(string)
		if !ok {
			return fmt.Errorf("jws: invalid type of payload: %T", payloadAny)
		}
		m.payload = []byte(payload)
	}

	sigsAny, hasSigs := raw["signatures"]
	sigAny, flattened := raw["signature"]

	if hasSigs && flattened {
		return errors.New("jws: failed to parse JWS: both signatures and signature are set")
	}
	if !hasSigs && !flattened {
		return errors.New("jws: failed to parse JWS: neither signatures nor signature are set")
	}

	if flattened {
		sigs := map[string]any{
			"signature": sigAny,
		}
		if protected, ok := raw["protected"]; ok {
			sigs["protected"] = protected
		}
		if header, ok := raw["header"]; ok {
			sigs["header"] = header
		}
		sigsAny = []any{sigs}
	}

	sigsArray, ok := sigsAny.([]any)
	if !ok {
		return fmt.Errorf("jws: invalid type of signatures: %T", sigsAny)
	}
	// decode signatures
	signatures := make([]*Signature, 0, len(sigsArray))
	for i, sigAny := range sigsArray {
		var sig Signature

		sigObject, ok := sigAny.(map[string]any)
		if !ok {
			return fmt.Errorf("jws: invalid type of signatures[]: %T", sigAny)
		}

		// decode protected header
		if protectedAny, ok := sigObject["protected"]; ok {
			protectedString, ok := protectedAny.(string)
			if !ok {
				return fmt.Errorf("jws: invalid type of signatures[].protected: %T", protectedAny)
			}
			raw, err := b64.DecodeString(protectedString)
			if err != nil {
				return fmt.Errorf("jws: failed to parse protected header: %w", err)
			}
			protected := NewHeader()
			if err := protected.UnmarshalJSON(raw); err != nil {
				return fmt.Errorf("jws: failed to parse protected header: %w", err)
			}
			sig.rawProtected = []byte(protectedString)
			sig.protected = protected

			if i == 0 {
				m.nb64 = protected.nb64
			} else if m.nb64 != protected.nb64 {
				return errors.New("jws: failed to parse protected header: b64 is mismatch")
			}
		}

		// decode unprotected header
		if unprotectedAny, ok := sigObject["header"]; ok {
			unprotectedObject, ok := unprotectedAny.(map[string]any)
			if !ok {
				return fmt.Errorf("jws: invalid type of signatures[].header: %T", unprotectedAny)
			}
			header, err := decodeHeader(unprotectedObject)
			if err != nil {
				return fmt.Errorf("jws: failed to parse header: %w", err)
			}
			sig.header = header
		}

		// decode signature
		signatureAny, ok := sigObject["signature"]
		if !ok {
			return errors.New("jws: failed to parse signature: signature is missing")
		}
		signatureString, ok := signatureAny.(string)
		if !ok {
			return fmt.Errorf("jws: invalid type of signatures[].signature: %T", signatureAny)
		}
		signature, err := b64.DecodeString(signatureString)
		if err != nil {
			return fmt.Errorf("jws: failed to parse signature: %w", err)
		}
		sig.b64signature = []byte(signatureString)
		sig.signature = signature

		signatures = append(signatures, &sig)
	}
	m.Signatures = signatures

	*msg = m
	return nil
}

func (msg *Message) MarshalJSON() ([]byte, error) {
	raw := map[string]any{
		"payload": string(msg.payload),
	}
	if len(msg.Signatures) == 1 {
		// Flattened JWS JSON Serialization
		sig := msg.Signatures[0]
		raw["protected"] = string(sig.rawProtected)
		raw["signature"] = string(sig.b64signature)
	} else {
		// Complete JWS JSON Serialization Representation
		signatures := make([]any, 0, len(msg.Signatures))
		for _, sig := range msg.Signatures {
			raw := map[string]any{
				"protected": string(sig.rawProtected),
				"signature": string(sig.b64signature),
			}
			if sig.header != nil {
				raw["header"] = sig.header
			}
			signatures = append(signatures, raw)
		}
		raw["signatures"] = signatures
	}
	return json.Marshal(raw)
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
	if b64, ok := d.GetBoolean(jwa.Base64URLEncodePayloadKey); ok {
		h.nb64 = !b64
	}

	// verify critical parameter
CRIT_LOOP:
	for _, param1 := range h.crit {
		for _, param2 := range knownParams {
			if param1 == param2 {
				continue CRIT_LOOP
			}
		}
		d.SaveError(fmt.Errorf("jws: unknown parameter is in crit: %q", param1))
	}

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

	if nb64 := h.nb64; nb64 {
		e.Set(jwa.Base64URLEncodePayloadKey, false)
	}

	if crit := h.crit; len(crit) > 0 {
		e.Set(jwa.CriticalKey, crit)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return e.Data(), nil
}

// Sign adds a new signature signed by key.
func (msg *Message) Sign(protected, header *Header, key sig.SigningKey) error {
	if msg.nb64 != protected.nb64 {
		return errors.New("jws: failed to sign: b64 is mismatch")
	}

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
	buf := make([]byte, 0, len(msg.payload)+len(raw)+1)
	buf = append(buf, raw...)
	buf = append(buf, '.')
	buf = append(buf, msg.payload...)
	signature, err := key.Sign(buf)
	if err != nil {
		return fmt.Errorf("jws: failed to sign: %w", err)
	}

	msg.Signatures = append(msg.Signatures, &Signature{
		protected:    protected,
		header:       header,
		rawProtected: raw,
		b64signature: b64Encode(signature),
		signature:    signature,
	})
	return nil
}

// Compact encodes JWS Signature into Compact Serialization.
func (msg *Message) Compact() ([]byte, error) {
	if len(msg.Signatures) != 1 {
		return nil, fmt.Errorf("jws: invalid number of signatures: %d", len(msg.Signatures))
	}
	sig := msg.Signatures[0]

	if msg.nb64 && bytes.IndexByte(msg.payload, '.') >= 0 {
		buf := make([]byte, 0, len(sig.rawProtected)+len(sig.b64signature)+2)
		buf = append(buf, sig.rawProtected...)
		buf = append(buf, '.')
		buf = append(buf, '.')
		buf = append(buf, sig.b64signature...)
		return buf, nil
	}
	buf := make([]byte, 0, len(sig.rawProtected)+len(msg.payload)+len(sig.b64signature)+2)
	buf = append(buf, sig.rawProtected...)
	buf = append(buf, '.')
	buf = append(buf, msg.payload...)
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
