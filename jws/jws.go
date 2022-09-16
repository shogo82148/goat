// Package jws handles JSON Web Signatures in [RFC7515].
package jws

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/url"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
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
	FindKey(ctx context.Context, header *Header) (h func() hash.Hash, key []byte, err error)
}

var dot = []byte{'.'}

func Parse(ctx context.Context, data []byte, finder KeyFinder) (*Message, error) {
	header, payload, signature, ok := split(data)
	if !ok {
		return nil, errors.New("jws: failed to parse JWS: invalid format")
	}

	var h map[string]any
	dec := json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(header)))
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("jws: failed to parse JWS: %w", err)
	}

	hash, key, err := finder.FindKey(ctx, &Header{})
	if err != nil {
		return nil, fmt.Errorf("jws: failed to find key: %w", err)
	}
	mac := hmac.New(hash, key)
	mac.Write(header)
	mac.Write(dot)
	mac.Write(payload)

	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, errors.New("jws: failed to parse JWS: signature mismatch")
	}

	return &Message{
		Header: &Header{
			Raw: h,
		},
		Payload: payload,
	}, nil
}

func split(data []byte) (header []byte, payload []byte, signature []byte, ok bool) {
	idx1 := bytes.IndexByte(data, '.')
	if idx1 < 0 {
		ok = false
		return
	}
	header = data[:idx1]
	data = data[idx1+1:]

	idx2 := bytes.IndexByte(data, '.')
	if idx2 < 0 {
		ok = false
		return
	}
	payload = data[:idx2]
	signature = data[idx2+1:]
	ok = true
	return
}
