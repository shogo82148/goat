// Package jws handles JSON Web Encryption defined in RFC 7516.
package jwe

import (
	"bytes"
	"compress/flate"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/keymanage"
)

var b64 = base64.RawURLEncoding

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	alg     jwa.KeyManagementAlgorithm
	enc     jwa.EncryptionAlgorithm
	zip     jwa.CompressionAlgorithm
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
	epk     *jwk.Key
	apu     []byte
	apv     []byte
	iv      []byte
	tag     []byte
	p2s     []byte
	p2c     int

	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// Clone returns a shallow copy of h.
func (h *Header) Clone() *Header {
	if h == nil {
		return &Header{
			Raw: make(map[string]any),
		}
	}
	clone := *h
	raw := make(map[string]any, len(h.Raw))
	for k, v := range h.Raw {
		raw[k] = v
	}
	clone.Raw = raw
	return &clone
}

// Algorithm returns the key management algorithm
// defined in RFC7516 Section 4.1.1. "alg" (Algorithm) Header Parameter.
func (h *Header) Algorithm() jwa.KeyManagementAlgorithm {
	if h == nil {
		return ""
	}
	return h.alg
}

func (h *Header) SetAlgorithm(alg jwa.KeyManagementAlgorithm) {
	h.alg = alg
}

// Encryption return the encryption algorithm
// defined in RFC7516 Section 4.1.2. "enc" (Encryption Algorithm) Header Parameter.
func (h *Header) EncryptionAlgorithm() jwa.EncryptionAlgorithm {
	if h == nil {
		return ""
	}
	return h.enc
}

func (h *Header) SetEncryptionAlgorithm(enc jwa.EncryptionAlgorithm) {
	h.enc = enc
}

// Compression is RFC7516 Section 4.1.3. "zip" (zip Algorithm) Header Parameter.
func (h *Header) CompressionAlgorithm() jwa.CompressionAlgorithm {
	if h == nil {
		return ""
	}
	return h.zip
}

func (h *Header) SetCompressionAlgorithm(zip jwa.CompressionAlgorithm) {
	h.zip = zip
}

// JWKSetURL is RFC7516 Section 4.1.4. "jku" (JWK Set URL) Header Parameter.
func (h *Header) JWKSetURL() *url.URL {
	if h == nil {
		return nil
	}
	return h.jku
}

func (h *Header) SetJWKSetURL(jku *url.URL) {
	h.jku = jku
}

// JWK is RFC7516 Section 4.1.5. "jwk" (JSON Web Key) Header Parameter.
func (h *Header) JWK() *jwk.Key {
	if h == nil {
		return nil
	}
	return h.jwk
}

func (h *Header) SetJWK(jwk *jwk.Key) {
	h.jwk = jwk
}

// KeyID is RFC7516 Section 4.1.6. "kid" (Key ID) Header Parameter.
func (h *Header) KeyID() string {
	if h == nil {
		return ""
	}
	return h.kid
}

func (h *Header) SetKeyID(kid string) {
	h.kid = kid
}

// X509URL is RFC7516 Section 4.1.7. "x5u" (X.509 URL) Header Parameter.
func (h *Header) X509URL() *url.URL {
	return h.x5u
}

func (h *Header) SetX509URL(x5u *url.URL) {
	h.x5u = x5u
}

// X509CertificateChain is RFC7516 Section 4.1.8. "x5c" (X.509 Certificate Chain) Header Parameter.
func (h *Header) X509CertificateChain() []*x509.Certificate {
	if h == nil {
		return nil
	}
	return h.x5c
}

func (h *Header) SetX509CertificateChain(x5c []*x509.Certificate) {
	h.x5c = x5c
}

// X509CertificateSHA1 is RFC7516 Section 4.1.9. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA1() []byte {
	if h == nil {
		return nil
	}
	return h.x5t
}

func (h *Header) SetX509CertificateSHA1(x5t []byte) {
	h.x5t = x5t
}

// X509CertificateSHA256 is RFC7516 Section 4.1.10. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA256() []byte {
	if h == nil {
		return nil
	}
	return h.x5tS256
}

func (h *Header) SetX509CertificateSHA256(x5tS256 []byte) {
	h.x5tS256 = x5tS256
}

// Type is RFC7516 Section 4.1.11. "typ" (Type) Header Parameter.
func (h *Header) Type() string {
	if h == nil {
		return ""
	}
	return h.typ
}

func (h *Header) SetType(typ string) {
	h.typ = typ
}

// ContentType is RFC7516 Section 4.1.12. "cty" (Content Type) Header Parameter.
func (h *Header) ContentType() string {
	if h == nil {
		return ""
	}
	return h.cty
}

func (h *Header) SetContentType(cty string) {
	h.cty = cty
}

// Critical is RFC7516 Section 4.1.13. "crit" (Critical) Header Parameter.
func (h *Header) Critical() []string {
	if h == nil {
		return nil
	}
	return h.crit
}

func (h *Header) SetCritical(crit []string) {
	h.crit = crit
}

// EphemeralPublicKey is RFC7518 Section 4.6.1.1. "epk" (Ephemeral Public Key) Header Parameter.
func (h *Header) EphemeralPublicKey() *jwk.Key {
	if h == nil {
		return nil
	}
	return h.epk
}

func (h *Header) SetEphemeralPublicKey(epk *jwk.Key) {
	h.epk = epk
}

// AgreementPartyUInfo is RFC7518 Section 4.6.1.2. "apu" (Agreement PartyUInfo) Header Parameter
func (h *Header) AgreementPartyUInfo() []byte {
	if h == nil {
		return nil
	}
	return h.apu
}

func (h *Header) SetAgreementPartyUInfo(apu []byte) {
	h.apu = apu
}

// AgreementPartyVInfo is RFC7518 Section 4.6.1.3. "apv" (Agreement PartyVInfo) Header Parameter
func (h *Header) AgreementPartyVInfo() []byte {
	if h == nil {
		return nil
	}
	return h.apv
}

func (h *Header) SetAgreementPartyVInfo(apv []byte) {
	h.apv = apv
}

// InitializationVector is RFC7518 Section 4.7.1.1. "iv" (Initialization Vector) Header Parameter.
// It is the 96-bit IV value used for the key encryption operation.
func (h *Header) InitializationVector() []byte {
	if h == nil {
		return nil
	}
	return h.iv
}

func (h *Header) SetInitializationVector(iv []byte) {
	h.iv = iv
}

// AuthenticationTag is RFC7518 Section 4.7.1.2. "tag" (Authentication Tag) Header Parameter.
func (h *Header) AuthenticationTag() []byte {
	if h == nil {
		return nil
	}
	return h.tag
}

func (h *Header) SetAuthenticationTag(tag []byte) {
	h.tag = tag
}

// PBES2SaltInput is the PBES2 salt input
// defined in RFC7518 Section 4.8.1.1. "p2s" (PBES2 Salt Input) Header Parameter.
func (h *Header) PBES2SaltInput() []byte {
	if h == nil {
		return nil
	}
	return h.p2s
}

func (h *Header) SetPBES2SaltInput(p2s []byte) {
	h.p2s = p2s
}

// PBES2Count is the PBES2 Count
// defined in RFC7518 Section 4.8.1.2. "p2c" (PBES2 Count) Header Parameter.
func (h *Header) PBES2Count() int {
	if h == nil {
		return 0
	}
	return h.p2c
}

func (h *Header) SetPBES2Count(p2c int) {
	if p2c < 0 {
		panic("jwe: p2c is out of range")
	}
	h.p2c = p2c
}

func (h *Header) MarshalJSON() ([]byte, error) {
	raw, err := encodeHeader(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(raw)
}

func (h *Header) UnmarshalJSON(data []byte) error {
	raw := make(map[string]any)
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

type mergedHeader []*Header

func (h mergedHeader) Algorithm() jwa.KeyManagementAlgorithm {
	for _, item := range h {
		if alg := item.alg; alg != "" {
			return alg
		}
	}
	return ""
}

func (h mergedHeader) SetAlgorithm(alg jwa.KeyManagementAlgorithm) {
	h[0].alg = alg
}

func (h mergedHeader) EncryptionAlgorithm() jwa.EncryptionAlgorithm {
	for _, item := range h {
		if enc := item.EncryptionAlgorithm(); enc != "" {
			return enc
		}
	}
	return ""
}

func (h mergedHeader) SetEncryptionAlgorithm(enc jwa.EncryptionAlgorithm) {
	h[0].enc = enc
}

func (h mergedHeader) CompressionAlgorithm() jwa.CompressionAlgorithm {
	for _, item := range h {
		if zip := item.CompressionAlgorithm(); zip != "" {
			return zip
		}
	}
	return ""
}

func (h mergedHeader) SetCompressionAlgorithm(zip jwa.CompressionAlgorithm) {
	h[0].zip = zip
}

func (h mergedHeader) JWKSetURL() *url.URL {
	for _, item := range h {
		if jku := item.JWKSetURL(); jku != nil {
			return jku
		}
	}
	return nil
}

func (h mergedHeader) SetJWKSetURL(jku *url.URL) {
	h[0].jku = jku
}

func (h mergedHeader) JWK() *jwk.Key {
	for _, item := range h {
		if jwk := item.JWK(); jwk != nil {
			return jwk
		}
	}
	return nil
}

func (h mergedHeader) SetJWK(jwk *jwk.Key) {
	h[0].jwk = jwk
}

func (h mergedHeader) KeyID() string {
	for _, item := range h {
		if kid := item.KeyID(); kid != "" {
			return kid
		}
	}
	return ""
}

func (h mergedHeader) SetKeyID(kid string) {
	h[0].kid = kid
}

func (h mergedHeader) X509URL() *url.URL {
	for _, item := range h {
		if x5u := item.X509URL(); x5u != nil {
			return x5u
		}
	}
	return nil
}

func (h mergedHeader) SetX509URL(x5u *url.URL) {
	h[0].x5u = x5u
}

func (h mergedHeader) X509CertificateChain() []*x509.Certificate {
	for _, item := range h {
		if x5c := item.X509CertificateChain(); x5c != nil {
			return x5c
		}
	}
	return nil
}

func (h mergedHeader) SetX509CertificateChain(x5c []*x509.Certificate) {
	h[0].x5c = x5c
}

func (h mergedHeader) X509CertificateSHA1() []byte {
	for _, item := range h {
		if x5t := item.X509CertificateSHA1(); x5t != nil {
			return x5t
		}
	}
	return nil
}

func (h mergedHeader) SetX509CertificateSHA1(x5t []byte) {
	h[0].x5t = x5t
}

func (h mergedHeader) X509CertificateSHA256() []byte {
	for _, item := range h {
		if x5tS256 := item.X509CertificateSHA256(); x5tS256 != nil {
			return x5tS256
		}
	}
	return nil
}

func (h mergedHeader) SetX509CertificateSHA256(x5tS256 []byte) {
	h[0].x5tS256 = x5tS256
}

func (h mergedHeader) Type() string {
	for _, item := range h {
		if typ := item.Type(); typ != "" {
			return typ
		}
	}
	return ""
}

func (h mergedHeader) SetType(typ string) {
	h[0].typ = typ
}

func (h mergedHeader) ContentType() string {
	for _, item := range h {
		if cty := item.ContentType(); cty != "" {
			return cty
		}
	}
	return ""
}

func (h mergedHeader) SetContentType(cty string) {
	h[0].cty = cty
}

func (h mergedHeader) Critical() []string {
	for _, item := range h {
		if crit := item.Critical(); crit != nil {
			return crit
		}
	}
	return nil
}

func (h mergedHeader) SetCritical(crit []string) {
	h[0].crit = crit
}

func (h mergedHeader) EphemeralPublicKey() *jwk.Key {
	for _, item := range h {
		if epk := item.EphemeralPublicKey(); epk != nil {
			return epk
		}
	}
	return nil
}

func (h mergedHeader) SetEphemeralPublicKey(epk *jwk.Key) {
	h[0].epk = epk
}

func (h mergedHeader) AgreementPartyUInfo() []byte {
	for _, item := range h {
		if apu := item.AgreementPartyUInfo(); apu != nil {
			return apu
		}
	}
	return nil
}

func (h mergedHeader) SetAgreementPartyUInfo(apu []byte) {
	h[0].apu = apu
}

func (h mergedHeader) AgreementPartyVInfo() []byte {
	for _, item := range h {
		if apv := item.AgreementPartyVInfo(); apv != nil {
			return apv
		}
	}
	return nil
}

func (h mergedHeader) SetAgreementPartyVInfo(apv []byte) {
	h[0].apv = apv
}

func (h mergedHeader) InitializationVector() []byte {
	for _, item := range h {
		if iv := item.InitializationVector(); iv != nil {
			return iv
		}
	}
	return nil
}

func (h mergedHeader) SetInitializationVector(iv []byte) {
	h[0].iv = iv
}

func (h mergedHeader) AuthenticationTag() []byte {
	for _, item := range h {
		if tag := item.AuthenticationTag(); tag != nil {
			return tag
		}
	}
	return nil
}

func (h mergedHeader) SetAuthenticationTag(tag []byte) {
	h[0].tag = tag
}

func (h mergedHeader) PBES2SaltInput() []byte {
	for _, item := range h {
		if p2s := item.PBES2SaltInput(); p2s != nil {
			return p2s
		}
	}
	return nil
}

func (h mergedHeader) SetPBES2SaltInput(p2s []byte) {
	h[0].p2s = p2s
}

func (h mergedHeader) PBES2Count() int {
	for _, item := range h {
		if p2c := item.PBES2Count(); p2c != 0 {
			return p2c
		}
	}
	return 0
}

func (h mergedHeader) SetPBES2Count(p2c int) {
	if p2c < 0 {
		panic("jwe: p2c is out of range")
	}
	h[0].p2c = p2c
}

// Message is a decoded JWS.
type Message struct {
	UnprotectedHeader *Header
	Recipients        []*Recipient

	header                    *Header
	cek                       []byte
	iv, b64iv                 []byte
	ciphertext, b64ciphertext []byte
	protected, b64protected   []byte
	tag, b64tag               []byte
}

type Recipient struct {
	header          *Header
	encryptedKey    []byte
	b64encryptedKey []byte
}

func NewMessage(enc jwa.EncryptionAlgorithm, protected *Header, plaintext []byte) (*Message, error) {
	if !enc.Available() {
		return nil, errors.New("jwa: requested content encryption algorithm " + string(enc) + " is not available")
	}

	if protected.CompressionAlgorithm() == jwa.DEF {
		buf := bytes.NewBuffer(make([]byte, 0, len(plaintext)))
		w, err := flate.NewWriter(buf, flate.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		if _, err := w.Write(plaintext); err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		plaintext = buf.Bytes()
	}

	// generate a new content encryption key
	enc1 := enc.New()
	cek, err := enc1.GenerateCEK()
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to generate content encryption key: %w", err)
	}
	iv, err := enc1.GenerateIV()
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to generate initialization vector: %w", err)
	}

	// encode the protected header
	header := protected.Clone()
	header.SetEncryptionAlgorithm(enc)
	rawHeader, err := header.MarshalJSON()
	if err != nil {
		return nil, err
	}
	b64header := b64Encode(rawHeader)

	// encrypt CEK
	ciphertext, authTag, err := enc1.Encrypt(cek, iv, b64header, plaintext)
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to encrypt: %w", err)
	}

	return &Message{
		header:        header,
		cek:           cek,
		iv:            iv,
		b64iv:         b64Encode(iv),
		ciphertext:    ciphertext,
		b64ciphertext: b64Encode(ciphertext),
		protected:     rawHeader,
		b64protected:  b64header,
		tag:           authTag,
		b64tag:        b64Encode(authTag),
	}, nil
}

func NewMessageWithKW(enc jwa.EncryptionAlgorithm, kw keymanage.KeyWrapper, protected *Header, plaintext []byte) (*Message, error) {
	if !enc.Available() {
		return nil, errors.New("jwa: requested content encryption algorithm " + string(enc) + " is not available")
	}

	if protected.CompressionAlgorithm() == jwa.DEF {
		buf := bytes.NewBuffer(make([]byte, 0, len(plaintext)))
		w, err := flate.NewWriter(buf, flate.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		if _, err := w.Write(plaintext); err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("jwe: failed compress content: %w", err)
		}
		plaintext = buf.Bytes()
	}

	if deriver, ok := kw.(keymanage.KeyDeriver); ok {
		header := protected.Clone()
		header.SetEncryptionAlgorithm(enc)
		cek, encryptedCEK, err := deriver.DeriveKey(header)
		if err != nil {
			return nil, err
		}

		// encode the header
		rawHeader, err := header.MarshalJSON()
		if err != nil {
			return nil, err
		}
		b64header := b64Encode(rawHeader)

		// encrypt CEK
		enc1 := enc.New()
		iv, err := enc1.GenerateIV()
		if err != nil {
			return nil, fmt.Errorf("jwe: failed to generate initialization vector: %w", err)
		}
		ciphertext, authTag, err := enc.New().Encrypt(cek, iv, b64header, plaintext)
		if err != nil {
			return nil, fmt.Errorf("jwe: failed to encrypt: %w", err)
		}

		return &Message{
			header:        header,
			cek:           cek,
			iv:            iv,
			b64iv:         b64Encode(iv),
			ciphertext:    ciphertext,
			b64ciphertext: b64Encode(ciphertext),
			protected:     rawHeader,
			b64protected:  b64header,
			tag:           authTag,
			b64tag:        b64Encode(authTag),
			Recipients: []*Recipient{
				{
					encryptedKey:    encryptedCEK,
					b64encryptedKey: b64Encode(encryptedCEK),
				},
			},
		}, nil
	}

	// generate a new content encryption key
	enc1 := enc.New()
	cek, err := enc1.GenerateCEK()
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to generate content encryption key: %w", err)
	}
	iv, err := enc1.GenerateIV()
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to generate initialization vector: %w", err)
	}

	header := protected.Clone()
	encryptedKey, err := kw.WrapKey(cek, header)
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to encrypt key: %w", err)
	}

	// encode the protected header
	header.SetEncryptionAlgorithm(enc)
	rawHeader, err := header.MarshalJSON()
	if err != nil {
		return nil, err
	}
	b64header := b64Encode(rawHeader)

	// encrypt CEK
	ciphertext, authTag, err := enc1.Encrypt(cek, iv, b64header, plaintext)
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to encrypt: %w", err)
	}

	return &Message{
		header:        header,
		cek:           cek,
		iv:            iv,
		b64iv:         b64Encode(iv),
		ciphertext:    ciphertext,
		b64ciphertext: b64Encode(ciphertext),
		protected:     rawHeader,
		b64protected:  b64header,
		tag:           authTag,
		b64tag:        b64Encode(authTag),
		Recipients: []*Recipient{
			{
				encryptedKey:    encryptedKey,
				b64encryptedKey: b64Encode(encryptedKey),
			},
		},
	}, nil
}

// KeyWrapperFinder is a wrapper for the FindKeyWrapper method.
type KeyWrapperFinder interface {
	FindKeyWrapper(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error)
}

var _ KeyWrapperFinder = FindKeyWrapperFunc(nil)

type FindKeyWrapperFunc func(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error)

func (f FindKeyWrapperFunc) FindKeyWrapper(protected, unprotected, recipient *Header) (wrapper keymanage.KeyWrapper, err error) {
	return f(protected, unprotected, recipient)
}

func (msg *Message) Decrypt(finder KeyWrapperFinder) (plaintext []byte, err error) {
	for _, r := range msg.Recipients {
		kw, err := finder.FindKeyWrapper(msg.header, msg.UnprotectedHeader, r.header)
		if err != nil {
			continue
		}
		merged := mergedHeader{
			msg.UnprotectedHeader,
			msg.header,
			r.header,
		}
		cek, err := kw.UnwrapKey(r.encryptedKey, merged)
		if err != nil {
			return nil, fmt.Errorf("jwe: failed to unwrap key: %w", err)
		}
		enc0 := msg.header.EncryptionAlgorithm()
		if !enc0.Available() {
			return nil, errors.New("jwa: requested content encryption algorithm " + string(enc0) + " is not available")
		}
		enc := enc0.New()
		plaintext, err := enc.Decrypt(cek, msg.iv, msg.b64protected, msg.ciphertext, msg.tag)
		if err != nil {
			return nil, fmt.Errorf("jwe: failed to decrypt: %w", err)
		}
		if merged.CompressionAlgorithm() == jwa.DEF {
			buf := bytes.NewBuffer(make([]byte, 0, len(plaintext)))
			r := flate.NewReader(bytes.NewReader(plaintext))
			if _, err := buf.ReadFrom(r); err != nil {
				return nil, fmt.Errorf("jwe: failed to decompress content: %w", err)
			}
			plaintext = buf.Bytes()
		}
		return plaintext, nil
	}
	return nil, errors.New("jwe: key wrapper not found")
}

func (msg *Message) Encrypt(kw keymanage.KeyWrapper, header *Header) error {
	h := header.Clone()
	data, err := kw.WrapKey(msg.cek, h)
	if err != nil {
		return fmt.Errorf("jwe: failed to encrypt key: %w", err)
	}
	msg.Recipients = append(msg.Recipients, &Recipient{
		header:          h,
		encryptedKey:    data,
		b64encryptedKey: b64Encode(data),
	})
	return nil
}

// Parse parses a Compact Serialized JWE.
func Parse(data []byte) (*Message, error) {
	// split to segments
	idx1 := bytes.IndexByte(data, '.')
	if idx1 < 0 {
		return nil, errors.New("jwe: failed to parse JWE: invalid format")
	}
	idx2 := bytes.IndexByte(data[idx1+1:], '.')
	if idx2 < 0 {
		return nil, errors.New("jwe: failed to parse JWE: invalid format")
	}
	idx2 += idx1 + 1
	idx3 := bytes.IndexByte(data[idx2+1:], '.')
	if idx3 < 0 {
		return nil, errors.New("jwe: failed to parse JWE: invalid format")
	}
	idx3 += idx2 + 1
	idx4 := bytes.IndexByte(data[idx3+1:], '.')
	if idx3 < 0 {
		return nil, errors.New("jwe: failed to parse JWE: invalid format")
	}
	idx4 += idx3 + 1

	data = append([]byte(nil), data...)
	b64header := data[:idx1]
	b64encryptedKey := data[idx1+1 : idx2]
	b64iv := data[idx2+1 : idx3]
	b64ciphertext := data[idx3+1 : idx4]
	b64tag := data[idx4+1:]

	// parse the header
	rawHeader, err := b64Decode(b64header)
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to decode header: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(rawHeader))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("jwe: failed to decode header: %w", err)
	}
	h, err := decodeHeader(raw)
	if err != nil {
		return nil, err
	}

	iv, err := b64Decode(b64iv)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := b64Decode(b64encryptedKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64Decode(b64ciphertext)
	if err != nil {
		return nil, err
	}
	tag, err := b64Decode(b64tag)
	if err != nil {
		return nil, err
	}

	return &Message{
		header:        h,
		iv:            iv,
		b64iv:         b64iv,
		ciphertext:    ciphertext,
		b64ciphertext: b64ciphertext,
		b64protected:  b64header,
		tag:           tag,
		b64tag:        b64tag,
		Recipients: []*Recipient{
			{
				encryptedKey:    encryptedKey,
				b64encryptedKey: b64encryptedKey,
			},
		},
	}, nil
}

func (msg *Message) Compact() ([]byte, error) {
	if len(msg.Recipients) != 1 {
		return nil, errors.New("jwe: invalid recipients number in compact serialization")
	}
	if msg.UnprotectedHeader != nil {
		return nil, errors.New("jwe: unprotected header is not allowed in compact serialization")
	}
	r := msg.Recipients[0]
	if r.header != nil {
		return nil, errors.New("jwe: recipient header is not allowed in compact serialization")
	}

	data := make([]byte, 0)
	data = append(data, msg.b64protected...)
	data = append(data, '.')
	data = append(data, r.b64encryptedKey...)
	data = append(data, '.')
	data = append(data, msg.b64iv...)
	data = append(data, '.')
	data = append(data, msg.b64ciphertext...)
	data = append(data, '.')
	data = append(data, msg.b64tag...)
	return data, nil
}

func b64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, b64.DecodedLen(len(src)))
	n, err := b64.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func decodeHeader(raw map[string]any) (*Header, error) {
	d := jsonutils.NewDecoder("jws", raw)
	h := &Header{
		Raw: raw,
	}

	if alg, ok := d.GetString(jwa.AlgorithmKey); ok {
		h.alg = jwa.KeyManagementAlgorithm(alg)
	}

	if enc, ok := d.GetString(jwa.EncryptionAlgorithmKey); ok {
		h.enc = jwa.EncryptionAlgorithm(enc)
	}

	if zip, ok := d.GetString(jwa.CompressionAlgorithmKey); ok {
		h.zip = jwa.CompressionAlgorithm(zip)
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
				d.SaveError(fmt.Errorf("jwe: failed to parse the parameter x5c[%d]: %w", i, err))
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				d.SaveError(fmt.Errorf("jwe: failed to parse certificate: %w", err))
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
				d.SaveError(errors.New("jwe: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	if x5t256, ok := d.GetBytes(jwa.X509CertificateSHA256Thumbprint); ok {
		h.x5tS256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwe: sha-256 thumbprint of certificate is mismatch"))
			}
		}
	}

	h.kid, _ = d.GetString(jwa.KeyIDKey)
	h.typ, _ = d.GetString(jwa.TypeKey)
	h.cty, _ = d.GetString(jwa.ContentTypeKey)
	h.crit, _ = d.GetStringArray(jwa.CriticalKey)

	// Header Parameters Used for ECDH Key Agreement
	if epk, ok := d.GetObject(jwa.EphemeralPublicKeyKey); ok {
		key, err := jwk.ParseMap(epk)
		if err == nil {
			h.epk = key
		} else {
			d.SaveError(fmt.Errorf("jwe: failed to parse epk: %w", err))
		}
	}
	if apu, ok := d.GetBytes(jwa.AgreementPartyUInfoKey); ok {
		h.apu = apu
	}
	if apv, ok := d.GetBytes(jwa.AgreementPartyVInfoKey); ok {
		h.apv = apv
	}

	// Header Parameter used for Key wrapping with AES GCM.
	if iv, ok := d.GetBytes(jwa.InitializationVectorKey); ok {
		h.iv = iv
	}
	if tag, ok := d.GetBytes(jwa.AuthenticationTagKey); ok {
		h.tag = tag
	}

	// Header Parameters Used for PBES2 Key Encryption
	if p2s, ok := d.GetBytes(jwa.PBES2SaltInputKey); ok {
		h.p2s = p2s
	}
	if p2c, ok := d.GetInt64(jwa.PBES2CountKey); ok {
		if p2c < 0 || p2c > math.MaxInt {
			d.SaveError(errors.New("jwe: p2c is out of range"))
		}
		h.p2c = int(p2c)
	}

	if err := d.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func b64Encode(src []byte) []byte {
	dst := make([]byte, b64.EncodedLen(len(src)))
	b64.Encode(dst, src)
	return dst
}

func encodeHeader(h *Header) (map[string]any, error) {
	raw := make(map[string]any, len(h.Raw))
	for k, v := range h.Raw {
		raw[k] = v
	}
	e := jsonutils.NewEncoder(raw)
	if v := h.alg; v != "" {
		e.Set(jwa.AlgorithmKey, string(v))
	}

	if enc := h.enc; enc != "" {
		e.Set(jwa.EncryptionAlgorithmKey, string(enc))
	}

	if zip := h.zip; zip != "" {
		e.Set(jwa.CompressionAlgorithmKey, zip.String())
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

	// Header Parameters Used for ECDH Key Agreement
	if epk := h.epk; epk != nil {
		e.Set(jwa.EphemeralPublicKeyKey, h.epk)
	}
	if apu := h.apu; apu != nil {
		e.SetBytes(jwa.AgreementPartyUInfoKey, apu)
	}
	if apv := h.apu; apv != nil {
		e.SetBytes(jwa.AgreementPartyVInfoKey, apv)
	}

	// Header Parameter used for Key wrapping with AES GCM.
	if iv := h.iv; iv != nil {
		e.SetBytes(jwa.InitializationVectorKey, iv)
	}
	if tag := h.tag; tag != nil {
		e.SetBytes(jwa.AuthenticationTagKey, tag)
	}

	// Header Parameters Used for PBES2 Key Encryption
	if p2s := h.p2s; p2s != nil {
		e.SetBytes(jwa.PBES2SaltInputKey, p2s)
	}
	if p2c := h.p2c; p2c != 0 {
		e.Set(jwa.PBES2CountKey, p2c)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return e.Data(), nil
}

func (msg *Message) MarshalJSON() ([]byte, error) {
	var unprotected map[string]any
	if msg.UnprotectedHeader != nil {
		var err error
		unprotected, err = encodeHeader(msg.UnprotectedHeader)
		if err != nil {
			return nil, err
		}
	}
	recipients := make([]jsonRecipient, 0, len(msg.Recipients))
	for _, r := range msg.Recipients {
		header, err := encodeHeader(r.header)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, jsonRecipient{
			Header:       header,
			EncryptedKey: string(r.b64encryptedKey),
		})
	}
	raw := jsonJWE{
		Unprotected: unprotected,
		Protected:   string(msg.b64protected),
		IV:          string(msg.b64iv),
		Ciphertext:  string(msg.b64ciphertext),
		Tag:         string(msg.b64tag),
		Recipients:  recipients,
	}
	return json.Marshal(raw)
}

func (msg *Message) UnmarshalJSON(data []byte) error {
	msg0, err := ParseJSON(data)
	if err != nil {
		return err
	}
	*msg = *msg0
	return nil
}

type jsonJWE struct {
	AAD         string          `json:"aad,omitempty"`
	Ciphertext  string          `json:"ciphertext"`
	IV          string          `json:"iv,omitempty"`
	Protected   string          `json:"protected"`
	Recipients  []jsonRecipient `json:"recipients"`
	Tag         string          `json:"tag,omitempty"`
	Unprotected map[string]any  `json:"unprotected,omitempty"`
}

type jsonRecipient struct {
	EncryptedKey string         `json:"encrypted_key"`
	Header       map[string]any `json:"header"`
}

func ParseJSON(data []byte) (*Message, error) {
	var raw jsonJWE
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	b64protected := []byte(raw.Protected)
	protected, err := b64Decode(b64protected)
	if err != nil {
		return nil, err
	}
	rawHeader, err := unmarshalJSON(protected)
	if err != nil {
		return nil, err
	}
	h, err := decodeHeader(rawHeader)
	if err != nil {
		return nil, err
	}

	unprotected, err := decodeHeader(raw.Unprotected)
	if err != nil {
		return nil, err
	}

	b64ciphertext := []byte(raw.Ciphertext)
	ciphertext, err := b64Decode(b64ciphertext)
	if err != nil {
		return nil, err
	}

	b64iv := []byte(raw.IV)
	iv, err := b64Decode(b64iv)
	if err != nil {
		return nil, err
	}
	b64tag := []byte(raw.Tag)
	tag, err := b64Decode(b64tag)
	if err != nil {
		return nil, err
	}

	recipients := make([]*Recipient, 0, len(raw.Recipients))
	for _, r := range raw.Recipients {
		header, err := decodeHeader(r.Header)
		if err != nil {
			return nil, err
		}
		b64encryptedKey := []byte(r.EncryptedKey)
		encryptedKey, err := b64Decode(b64encryptedKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, &Recipient{
			header:          header,
			b64encryptedKey: b64encryptedKey,
			encryptedKey:    encryptedKey,
		})
	}
	return &Message{
		UnprotectedHeader: unprotected,
		header:            h,
		iv:                iv,
		b64iv:             b64iv,
		ciphertext:        ciphertext,
		b64ciphertext:     b64ciphertext,
		protected:         protected,
		b64protected:      b64protected,
		tag:               tag,
		b64tag:            b64tag,
		Recipients:        recipients,
	}, nil
}

func unmarshalJSON(data []byte) (map[string]any, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewBuffer(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}
