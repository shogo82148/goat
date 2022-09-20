// Package jws handles JSON Web Signatures in [RFC7515].
package jws

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/goat/sig"
)

// Header is a decoded JSON Object Signing and Encryption (JOSE) Header.
type Header struct {
	// Algorithm is RFC7515 Section 4.1.1. "alg" (Algorithm) Header Parameter.
	Algorithm jwa.SignatureAlgorithm

	// JWKSetURL is RFC7515 Section 4.1.2. "jku" (JWK Set URL) Header Parameter.
	JWKSetURL *url.URL

	// JWK is RFC7515 Section 4.1.3. "jwk" (JSON Web Key) Header Parameter.
	JWK *jwk.Key

	// KeyID is RFC7515 Section 4.1.4. "kid" (Key ID) Header Parameter.
	KeyID string

	// X509URL is RFC7515 Section 4.1.5. "x5u" (X.509 URL) Header Parameter.
	X509URL string

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

	// Raw is the raw JWS Header.
	Raw map[string]any
}

// Message is a decoded JWS.
type Message struct {
	Header *Header

	Payload []byte
}

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	FindKey(ctx context.Context, header *Header) (key sig.Key, err error)
}

type FindKeyFunc func(ctx context.Context, header *Header) (key sig.Key, err error)

func (f FindKeyFunc) FindKey(ctx context.Context, header *Header) (key sig.Key, err error) {
	return f(ctx, header)
}

// Parse parses a JWS.
func Parse(ctx context.Context, data []byte, finder KeyFinder) (*Message, error) {
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

	// parse the header
	var raw map[string]any
	dec := json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(header)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("jws: failed to parse JOSE header: %w", err)
	}
	h, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}

	// decode signature
	size := len(signature)
	if len(payload) > size {
		size = len(payload)
	}
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(size))
	n, err := base64.RawURLEncoding.Decode(buf, signature)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse signature: %w", err)
	}
	buf = buf[:n]

	// find the key
	key, err := finder.FindKey(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to find key: %w", err)
	}

	// verify the signature
	if err := key.Verify(data[:idx2], buf); err != nil {
		return nil, err
	}

	// decode payload
	buf = buf[:cap(buf)]
	n, err = base64.RawURLEncoding.Decode(buf, payload)
	if err != nil {
		return nil, fmt.Errorf("jws: failed to parse payload: %w", err)
	}

	return &Message{
		Header:  h,
		Payload: buf[:n],
	}, nil
}

func parseHeader(raw map[string]any) (*Header, error) {
	d := jsonutils.NewDecoder("jws", raw)
	h := &Header{
		Raw: raw,
	}

	if alg, ok := d.GetString("alg"); ok {
		h.Algorithm = jwa.SignatureAlgorithm(alg)
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
		h.JWKSetURL = x5u
	}

	var cert0 []byte
	if x5c, ok := d.GetStringArray("x5c"); ok {
		var certs []*x509.Certificate
		for i, s := range x5c {
			der := d.DecodeStd(s, "x5c["+strconv.Itoa(i)+"]")
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
