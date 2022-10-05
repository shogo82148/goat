package jwe

import (
	"bytes"
	"context"
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
	Header *Header

	Plaintext []byte
}

// KeyWrapperFinder is a wrapper for the FindKeyWrapper method.
type KeyWrapperFinder interface {
	FindKeyWrapper(ctx context.Context, header *Header) (wrapper keymanage.KeyWrapper, err error)
}

type FindKeyWrapperFunc func(ctx context.Context, header *Header) (wrapper keymanage.KeyWrapper, err error)

func (f FindKeyWrapperFunc) FindKeyWrapper(ctx context.Context, header *Header) (wrapper keymanage.KeyWrapper, err error) {
	return f(ctx, header)
}

// Parse parses and decrypt a JWE.
func Parse(ctx context.Context, data []byte, finder KeyWrapperFinder) (*Message, error) {
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

	header := data[:idx1]
	encryptedKey := data[idx1+1 : idx2]
	initVector := data[idx2+1 : idx3]
	ciphertext := data[idx3+1 : idx4]
	authTag := data[idx4+1:]

	// parse the header
	var raw map[string]any
	dec := json.NewDecoder(base64.NewDecoder(b64, bytes.NewReader(header)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("jwe: failed to parse JOSE header: %w", err)
	}
	h, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}

	// Decrypt CEK
	wrapper, err := finder.FindKeyWrapper(ctx, h)
	if err != nil {
		return nil, err
	}
	encryptedRawKey, err := b64Decode(encryptedKey)
	if err != nil {
		return nil, err
	}
	cek, err := wrapper.UnwrapKey(encryptedRawKey, h)
	if err != nil {
		return nil, err
	}

	iv, err := b64Decode(initVector)
	if err != nil {
		return nil, err
	}
	rawCiphertext, err := b64Decode(ciphertext)
	if err != nil {
		return nil, err
	}
	rawAuthTag, err := b64Decode(authTag)
	if err != nil {
		return nil, err
	}

	// Decrypt the content
	enc := h.EncryptionAlgorithm()
	if !enc.Available() {
		return nil, errors.New("jwa: requested content encryption algorithm " + enc.String() + " is not available")
	}
	plaintext, err := enc.New().Decrypt(cek, iv, header, rawCiphertext, rawAuthTag)
	if err != nil {
		return nil, err
	}

	return &Message{
		Header:    h,
		Plaintext: plaintext,
	}, nil
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

func Encrypt(header *Header, plaintext []byte, keyWrapper keymanage.KeyWrapper) (ciphertext []byte, err error) {
	henc := header.EncryptionAlgorithm()
	if !henc.Available() {
		return nil, errors.New("jwa: requested content encryption algorithm " + string(henc) + " is not available")
	}
	enc := henc.New()
	entropy := make([]byte, enc.CEKSize()+enc.IVSize())
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	cek, iv := entropy[:enc.CEKSize()], entropy[enc.CEKSize():]
	encryptedKey, err := keyWrapper.WrapKey(cek, header)
	if err != nil {
		return nil, err
	}

	rawHeader, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}
	encodedHeader := b64Encode(rawHeader)
	payload, authTag, err := enc.Encrypt(cek, iv, encodedHeader, plaintext)
	if err != nil {
		return nil, err
	}
	ciphertext = encodedHeader
	ciphertext = append(ciphertext, '.')
	ciphertext = append(ciphertext, b64Encode(encryptedKey)...)
	ciphertext = append(ciphertext, '.')
	ciphertext = append(ciphertext, b64Encode(iv)...)
	ciphertext = append(ciphertext, '.')
	ciphertext = append(ciphertext, b64Encode(payload)...)
	ciphertext = append(ciphertext, '.')
	ciphertext = append(ciphertext, b64Encode(authTag)...)
	return ciphertext, nil
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
