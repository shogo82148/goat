package jwe

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
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
	return h.alg
}

func (h *Header) SetAlgorithm(alg jwa.KeyManagementAlgorithm) {
	h.alg = alg
}

// Encryption return the encryption algorithm
// defined in RFC7516 Section 4.1.2. "enc" (Encryption Algorithm) Header Parameter.
func (h *Header) EncryptionAlgorithm() jwa.EncryptionAlgorithm {
	return h.enc
}

func (h *Header) SetEncryptionAlgorithm(enc jwa.EncryptionAlgorithm) {
	h.enc = enc
}

// Compression is RFC7516 Section 4.1.3. "zip" (zip Algorithm) Header Parameter.
func (h *Header) CompressionAlgorithm() jwa.CompressionAlgorithm {
	return h.zip
}

func (h *Header) SetCompressionAlgorithm(zip jwa.CompressionAlgorithm) {
	h.zip = zip
}

// JWKSetURL is RFC7516 Section 4.1.4. "jku" (JWK Set URL) Header Parameter.
func (h *Header) JWKSetURL() *url.URL {
	return h.jku
}

func (h *Header) SetJWKSetURL(jku *url.URL) {
	h.jku = jku
}

// JWK is RFC7516 Section 4.1.5. "jwk" (JSON Web Key) Header Parameter.
func (h *Header) JWK() *jwk.Key {
	return h.jwk
}

func (h *Header) SetJWK(jwk *jwk.Key) {
	h.jwk = jwk
}

// KeyID is RFC7516 Section 4.1.6. "kid" (Key ID) Header Parameter.
func (h *Header) KeyID() string {
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
	return h.x5c
}

func (h *Header) SetX509CertificateChain(x5c []*x509.Certificate) {
	h.x5c = x5c
}

// X509CertificateSHA1 is RFC7516 Section 4.1.9. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA1() []byte {
	return h.x5t
}

func (h *Header) SetX509CertificateSHA1(x5t []byte) {
	h.x5t = x5t
}

// X509CertificateSHA256 is RFC7516 Section 4.1.10. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
func (h *Header) X509CertificateSHA256() []byte {
	return h.x5tS256
}

func (h *Header) SetX509CertificateSHA256(x5tS256 []byte) {
	h.x5tS256 = x5tS256
}

// Type is RFC7516 Section 4.1.11. "typ" (Type) Header Parameter.
func (h *Header) Type() string {
	return h.typ
}

func (h *Header) SetType(typ string) {
	h.typ = typ
}

// ContentType is RFC7516 Section 4.1.12. "cty" (Content Type) Header Parameter.
func (h *Header) ContentType() string {
	return h.cty
}

func (h *Header) SetContentType(cty string) {
	h.cty = cty
}

// Critical is RFC7516 Section 4.1.13. "crit" (Critical) Header Parameter.
func (h *Header) Critical() []string {
	return h.crit
}

func (h *Header) SetCritical(crit []string) {
	h.crit = crit
}

// EphemeralPublicKey is RFC7518 Section 4.6.1.1. "epk" (Ephemeral Public Key) Header Parameter.
func (h *Header) EphemeralPublicKey() *jwk.Key {
	return h.epk
}

func (h *Header) SetEphemeralPublicKey(epk *jwk.Key) {
	h.epk = epk
}

// AgreementPartyUInfo is RFC7518 Section 4.6.1.2. "apu" (Agreement PartyUInfo) Header Parameter
func (h *Header) AgreementPartyUInfo() []byte {
	return h.apu
}

func (h *Header) SetAgreementPartyUInfo(apu []byte) {
	h.apu = apu
}

// AgreementPartyVInfo is RFC7518 Section 4.6.1.3. "apv" (Agreement PartyVInfo) Header Parameter
func (h *Header) AgreementPartyVInfo() []byte {
	return h.apv
}

func (h *Header) SetAgreementPartyVInfo(apv []byte) {
	h.apv = apv
}

// InitializationVector is RFC7518 Section 4.7.1.1. "iv" (Initialization Vector) Header Parameter.
// It is the 96-bit IV value used for the key encryption operation.
func (h *Header) InitializationVector() []byte {
	return h.iv
}

func (h *Header) SetInitializationVector(iv []byte) {
	h.iv = iv
}

// AuthenticationTag is RFC7518 Section 4.7.1.2. "tag" (Authentication Tag) Header Parameter.
func (h *Header) AuthenticationTag() []byte {
	return h.tag
}

func (h *Header) SetAuthenticationTag(tag []byte) {
	h.tag = tag
}

// PBES2SaltInput is the PBES2 salt input
// defined in RFC7518 Section 4.8.1.1. "p2s" (PBES2 Salt Input) Header Parameter.
func (h *Header) PBES2SaltInput() []byte {
	return h.p2s
}

func (h *Header) SetPBES2SaltInput(p2s []byte) {
	h.p2s = p2s
}

// PBES2Count is the PBES2 Count
// defined in RFC7518 Section 4.8.1.2. "p2c" (PBES2 Count) Header Parameter.
func (h *Header) PBES2Count() int {
	return h.p2c
}

func (h *Header) SetPBES2Count(p2c int) {
	if p2c < 0 {
		panic("jwe: p2c is out of range")
	}
	h.p2c = p2c
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
	entropy := make([]byte, enc.CEKSize()+enc.IVSize())
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("jwe: failed to generate content encryption key")
	}
	cek, iv := entropy[:enc.CEKSize()], entropy[enc.CEKSize():]

	// encode the protected header
	header := protected.Clone()
	header.SetEncryptionAlgorithm(enc)
	rawHeader, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}
	b64header := b64Encode(rawHeader)

	// encrypt CEK
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
		rawHeader, err := encodeHeader(header)
		if err != nil {
			return nil, err
		}
		b64header := b64Encode(rawHeader)

		// encrypt CEK
		iv := make([]byte, enc.IVSize())
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("jwe: failed to generate content encryption key")
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
	entropy := make([]byte, enc.CEKSize()+enc.IVSize())
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("jwe: failed to generate content encryption key")
	}
	cek, iv := entropy[:enc.CEKSize()], entropy[enc.CEKSize():]

	header := protected.Clone()
	encryptedKey, err := kw.WrapKey(cek, header)
	if err != nil {
		return nil, fmt.Errorf("jwe: failed to encrypt key: %w", err)
	}

	// encode the protected header
	header.SetEncryptionAlgorithm(enc)
	rawHeader, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}
	b64header := b64Encode(rawHeader)

	// encrypt CEK
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
		cek, err := kw.UnwrapKey(r.encryptedKey, msg.header) // TODO: merge header
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
		if msg.header.CompressionAlgorithm() == jwa.DEF { // TODO: merge header
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
	h, err := parseHeader(raw)
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
	// TODO: validate header

	r := msg.Recipients[0]
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

func parseHeader(raw map[string]any) (*Header, error) {
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

func encodeHeader(h *Header) ([]byte, error) {
	raw := make(map[string]any, len(h.Raw))
	for k, v := range h.Raw {
		raw[k] = v
	}
	e := jsonutils.NewEncoder(raw)
	if v := h.alg; v != "" {
		e.Set("alg", string(v))
	}

	if enc := h.enc; enc != "" {
		e.Set("enc", string(enc))
	}

	if zip := h.zip; zip != "" {
		e.Set("zip", zip.String())
	}

	if u := h.jku; u != nil {
		e.Set("jku", u.String())
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
	return json.Marshal(e.Data())
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
	Protected   string          `json:"protected"`
	Unprotected map[string]any  `json:"unprotected,omitempty"`
	IV          string          `json:"iv,omitempty"`
	AAD         string          `json:"aad,omitempty"`
	Ciphertext  string          `json:"ciphertext"`
	Tag         string          `json:"tag,omitempty"`
	Recipients  []jsonRecipient `json:"recipients"`
}

type jsonRecipient struct {
	Header       map[string]any `json:"header"`
	EncryptedKey string         `json:"encrypted_key"`
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
	h, err := parseHeader(rawHeader)
	if err != nil {
		return nil, err
	}

	unprotected, err := parseHeader(raw.Unprotected)
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
		header, err := parseHeader(r.Header)
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
