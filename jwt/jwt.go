package jwt

import "time"

// Claims is a JWT Claims Set defined in RFC7519.
type Claims struct {
	// RFC7519 Section 4.1.1. "iss" (Issuer) Claim
	Issuer string

	// RFC7519 Section 4.1.2. "sub" (Subject) Claim
	Subject string

	// RFC7519 Section 4.1.3. "aud" (Audience) Claim
	Audience string

	// RFC7519 Section 4.1.4. "exp" (Expiration Time) Claim
	ExpirationTime time.Time

	// RFC7519 Section 4.1.5. "nbf" (Not Before) Claim
	NotBefore time.Time

	// RFC7519 Section 4.1.6. "iat" (Issued At) Claim
	IssuedAt time.Time

	// RFC7519 Section 4.1.7. "jti" (JWT ID) Claim
	JWTID string

	// Raw is a JSON-decoded data of the claims.
	Raw map[string]any
}
