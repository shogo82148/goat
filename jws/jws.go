// Package jws handles JSON Web Signatures in [RFC7515].
package jws

import (
	"crypto/x509"
	"net/url"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
)

// Header is the header of JWS.
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
