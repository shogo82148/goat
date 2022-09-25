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
	"github.com/shogo82148/goat/jwa/acbc"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/keymanage"
)

var b64 = base64.RawURLEncoding

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	// Algorithm is RFC7516 Section 4.1.1. "alg" (Algorithm) Header Parameter.
	Algorithm jwa.KeyManagementAlgorithm

	// Encryption is RFC7516 Section 4.1.1. "enc" (Encryption Algorithm) Header Parameter.
	Encryption jwa.EncryptionAlgorithm

	Zip string

	// JWKSetURL is RFC7515 Section 4.1.2. "jku" (JWK Set URL) Header Parameter.
	JWKSetURL *url.URL

	// JWK is RFC7515 Section 4.1.3. "jwk" (JSON Web Key) Header Parameter.
	JWK *jwk.Key

	// KeyID is RFC7515 Section 4.1.4. "kid" (Key ID) Header Parameter.
	KeyID string

	// X509URL is RFC7515 Section 4.1.5. "x5u" (X.509 URL) Header Parameter.
	X509URL *url.URL

	// X509CertificateChain is RFC7515 Section 4.1.6. "x5c" (X.509 Certificate Chain) Header Parameter.
	X509CertificateChain []*x509.Certificate

	// X509CertificateSHA1 is RFC7515 Section 4.1.7. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
	X509CertificateSHA1 []byte

	// X509CertificateSHA256 is RFC7517 Section 4.1.8. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter.
	X509CertificateSHA256 []byte

	// Type is RFC7517 Section 4.1.9. "typ" (Type) Header Parameter.
	Type string

	// ContentType is RFC7517 Section 4.1.10. "cty" (Content Type) Header Parameter.
	ContentType string

	// Critical is 4.1.11. "crit" (Critical) Header Parameter.
	Critical []string

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
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
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

	key := acbc.New128CBC_HS256().NewCEK(cek)
	rawCiphertext, err := b64Decode(ciphertext)
	if err != nil {
		return nil, err
	}
	rawAuthTag, err := b64Decode(authTag)
	if err != nil {
		return nil, err
	}
	plaintext, err := key.Decrypt(rand.Reader, iv, header, rawCiphertext, rawAuthTag)
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
		h.Zip = zip
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
		h.X509CertificateChain = certs
	}

	if x5t, ok := d.GetBytes("x5t"); ok {
		h.X509CertificateSHA1 = x5t
		if cert0 != nil {
			sum := sha1.Sum(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	if x5t256, ok := d.GetBytes("x5t#S256"); ok {
		h.X509CertificateSHA256 = x5t256
		if cert0 != nil {
			sum := sha256.Sum256(cert0)
			if subtle.ConstantTimeCompare(sum[:], x5t256) == 0 {
				d.SaveError(errors.New("jwk: sha-1 thumbprint of certificate is mismatch"))
			}
		}
	}

	h.KeyID, _ = d.GetString("kid")
	h.Type, _ = d.GetString("typ")
	h.ContentType, _ = d.GetString("cty")
	h.Critical, _ = d.GetStringArray("crit")

	if err := d.Err(); err != nil {
		return nil, err
	}
	return h, nil
}
