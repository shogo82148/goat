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
	"net/url"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/keymanage"
)

var b64 = base64.RawURLEncoding

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	// Algorithm is RFC7516 Section 4.1.1. "alg" (Algorithm) Header Parameter.
	Algorithm jwa.KeyManagementAlgorithm

	// Encryption is RFC7516 Section 4.1.2. "enc" (Encryption Algorithm) Header Parameter.
	Encryption jwa.EncryptionAlgorithm

	// Compression is RFC7516 Section 4.1.3. "zip" (Compression Algorithm) Header Parameter.
	Compression jwa.CompressionAlgorithm

	// JWKSetURL is RFC7516 Section 4.1.4. "jku" (JWK Set URL) Header Parameter.
	JWKSetURL *url.URL

	// JWK is RFC7516 Section 4.1.5. "jwk" (JSON Web Key) Header Parameter.
	JWK *jwk.Key

	// KeyID is RFC7516 Section 4.1.6. "kid" (Key ID) Header Parameter.
	KeyID string

	// X509URL is RFC7516 Section 4.1.7. "x5u" (X.509 URL) Header Parameter.
	X509URL *url.URL

	// X509CertificateChain is RFC7516 Section 4.1.8. "x5c" (X.509 Certificate Chain) Header Parameter.
	X509CertificateChain []*x509.Certificate

	// X509CertificateSHA1 is RFC7516 Section 4.1.9. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
	X509CertificateSHA1 []byte

	// X509CertificateSHA256 is RFC7516 Section 4.1.10. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
	X509CertificateSHA256 []byte

	// Type is RFC7516 Section 4.1.11. "typ" (Type) Header Parameter.
	Type string

	// ContentType is RFC7516 Section 4.1.12. "cty" (Content Type) Header Parameter.
	ContentType string

	// Critical is RFC7516 Section 4.1.13. "crit" (Critical) Header Parameter.
	Critical []string

	// EphemeralPublicKey is RFC7518 Section 4.6.1.1. "epk" (Ephemeral Public Key) Header Parameter.
	EphemeralPublicKey *jwk.Key

	// AgreementPartyUInfo is RFC7518 Section 4.6.1.2. "apu" (Agreement PartyUInfo) Header Parameter
	AgreementPartyUInfo []byte

	// AgreementPartyVInfo is RFC7518 Section 4.6.1.3. "apv" (Agreement PartyVInfo) Header Parameter
	AgreementPartyVInfo []byte

	// InitializationVector is RFC7518 Section 4.7.1.1. "iv" (Initialization Vector) Header Parameter.
	// It is the 96-bit IV value used for the key encryption operation.
	InitializationVector []byte

	// AuthenticationTag is RFC7518 Section 4.7.1.2. "tag" (Authentication Tag) Header Parameter.
	AuthenticationTag []byte

	// PBES2SaltInput is RFC7518 Section 4.8.1.1. "p2s" (PBES2 Salt Input) Header Parameter.
	PBES2SaltInput []byte

	// PBES2Count is RFC7518 Section 4.8.1.2. "p2c" (PBES2 Count) Header Parameter.
	PBES2Count int

	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
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
	cek, err := wrapper.UnwrapKey(encryptedRawKey)
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
	enc := h.Encryption
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

	if alg, ok := d.GetString("alg"); ok {
		h.Algorithm = jwa.KeyManagementAlgorithm(alg)
	}

	if enc, ok := d.GetString("enc"); ok {
		h.Encryption = jwa.EncryptionAlgorithm(enc)
	}

	if zip, ok := d.GetString("zip"); ok {
		h.Compression = jwa.CompressionAlgorithm(zip)
	}

	if jku, ok := d.GetURL("jku"); ok {
		h.JWKSetURL = jku
	}

	if v, ok := d.GetObject("jwk"); ok {
		key, err := jwk.ParseMap(v)
		if err != nil {
			d.SaveError(err)
		}
		h.JWK = key
	}

	if x5u, ok := d.GetURL("x5u"); ok {
		h.X509URL = x5u
	}

	var cert0 []byte
	if x5c, ok := d.GetStringArray("x5c"); ok {
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
		h.X509CertificateChain = certs
	}

	if x5t, ok := d.GetBytes("x5t"); ok {
		h.X509CertificateSHA1 = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.SaveError(errors.New("jwe: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	if x5t256, ok := d.GetBytes("x5t#S256"); ok {
		h.X509CertificateSHA256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwe: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	h.KeyID, _ = d.GetString("kid")
	h.Type, _ = d.GetString("typ")
	h.ContentType, _ = d.GetString("cty")
	h.Critical, _ = d.GetStringArray("crit")

	// Header Parameters Used for ECDH Key Agreement
	if epk, ok := d.GetObject("epk"); ok {
		key, err := jwk.ParseMap(epk)
		if err != nil {
			d.SaveError(fmt.Errorf("jwe: failed to parse epk: %w", err))
		} else {
			h.EphemeralPublicKey = key
		}
	}
	if apu, ok := d.GetBytes("apu"); ok {
		h.AgreementPartyUInfo = append([]byte(nil), apu...)
	}
	if apv, ok := d.GetBytes("apv"); ok {
		h.AgreementPartyVInfo = append([]byte(nil), apv...)
	}

	// Header Parameter used for Key wrapping with AES GCM.
	if iv, ok := d.GetBytes("iv"); ok {
		h.InitializationVector = append([]byte(nil), iv...)
	}
	if tag, ok := d.GetBytes("tag"); ok {
		h.AuthenticationTag = append([]byte(nil), tag...)
	}

	// Header Parameters Used for PBES2 Key Encryption
	if p2s, ok := d.GetBytes("p2s"); ok {
		h.PBES2SaltInput = append([]byte(nil), p2s...)
	}
	if p2c, ok := d.GetInt64("p2c"); ok {
		h.PBES2Count = int(p2c)
	}

	if err := d.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

func Encrypt(header *Header, plaintext []byte, keyWrapper keymanage.KeyWrapper) (ciphertext []byte, err error) {
	if !header.Encryption.Available() {
		return nil, errors.New("jwa: requested content encryption algorithm " + header.Encryption.String() + " is not available")
	}
	enc := header.Encryption.New()
	entropy := make([]byte, enc.CEKSize()+enc.IVSize())
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	cek, iv := entropy[:enc.CEKSize()], entropy[enc.CEKSize():]
	encryptedKey, err := keyWrapper.WrapKey(cek)
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
	if v := h.Algorithm; v != "" {
		e.Set("alg", v.String())
	}

	if enc := h.Encryption; enc != "" {
		e.Set("enc", enc.String())
	}

	if zip := h.Compression; zip != "" {
		e.Set("zip", zip.String())
	}

	if u := h.JWKSetURL; u != nil {
		e.Set("jku", u.String())
	}

	if key := h.JWK; key != nil {
		data, err := key.MarshalJSON()
		if err != nil {
			e.SaveError(err)
		} else {
			e.Set("jwk", json.RawMessage(data))
		}
	}

	if kid := h.KeyID; kid != "" {
		e.Set("kid", kid)
	}

	if x5u := h.X509URL; x5u != nil {
		e.Set("x5u", x5u.String())
	}

	if x5c := h.X509CertificateChain; x5c != nil {
		chain := make([][]byte, 0, len(x5c))
		for _, cert := range x5c {
			chain = append(chain, cert.Raw)
		}
		e.Set("x5c", chain)
	}
	if x5t := h.X509CertificateSHA1; x5t != nil {
		e.SetBytes("x5t", x5t)
	} else if len(h.X509CertificateChain) > 0 {
		cert := h.X509CertificateChain[0]
		sum := sha1.Sum(cert.Raw)
		e.SetBytes("x5t", sum[:])
	}
	if x5t256 := h.X509CertificateSHA256; x5t256 != nil {
		e.SetBytes("x5t#S256", x5t256)
	} else if len(h.X509CertificateChain) > 0 {
		cert := h.X509CertificateChain[0]
		sum := sha256.Sum256(cert.Raw)
		e.SetBytes("x5t#S256", sum[:])
	}

	if typ := h.Type; typ != "" {
		e.Set("typ", typ)
	}

	if cty := h.ContentType; cty != "" {
		e.Set("cty", cty)
	}

	if crit := h.Critical; len(crit) > 0 {
		e.Set("crit", crit)
	}

	// Header Parameters Used for ECDH Key Agreement
	if epk := h.EphemeralPublicKey; epk != nil {
		e.Set("epk", h.EphemeralPublicKey)
	}
	if apu := h.AgreementPartyUInfo; apu != nil {
		e.SetBytes("apu", apu)
	}
	if apv := h.AgreementPartyUInfo; apv != nil {
		e.SetBytes("apv", apv)
	}

	// Header Parameter used for Key wrapping with AES GCM.
	if iv := h.InitializationVector; iv != nil {
		e.SetBytes("iv", iv)
	}
	if tag := h.AuthenticationTag; tag != nil {
		e.SetBytes("tag", tag)
	}

	// Header Parameters Used for PBES2 Key Encryption
	if p2s := h.PBES2SaltInput; p2s != nil {
		e.SetBytes("p2s", p2s)
	}
	if p2c := h.PBES2Count; p2c != 0 {
		e.Set("p2c", p2c)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(e.Data())
}
