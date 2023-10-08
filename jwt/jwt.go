// Package jwt handles JSON Web Token defined in RFC 7519.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

var b64 = base64.RawURLEncoding
var nowFunc = time.Now // for testing

// Claims is a JWT Claims Set defined in RFC 7519.
type Claims struct {
	// RFC 7519 Section 4.1.1. "iss" (Issuer) Claim
	Issuer string

	// RFC 7519 Section 4.1.2. "sub" (Subject) Claim
	Subject string

	// RFC 7519 Section 4.1.3. "aud" (Audience) Claim
	Audience []string

	// RFC 7519 Section 4.1.4. "exp" (Expiration Time) Claim
	ExpirationTime time.Time

	// RFC 7519 Section 4.1.5. "nbf" (Not Before) Claim
	NotBefore time.Time

	// RFC 7519 Section 4.1.6. "iat" (Issued At) Claim
	IssuedAt time.Time

	// RFC 7519 Section 4.1.7. "jti" (JWT ID) Claim
	JWTID string

	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// Token is a decoded JWT token.
type Token struct {
	Header *jws.Header
	Claims *Claims
}

func Sign(header *jws.Header, claims *Claims, key sig.SigningKey) ([]byte, error) {
	payload, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	headerBytes, err := header.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to encode header: %w", err)
	}

	l1 := b64.EncodedLen(len(headerBytes))
	l2 := b64.EncodedLen(len(payload))
	buf := make([]byte, l1+l2+2+b64.EncodedLen(512))
	b64.Encode(buf[:l1], headerBytes)
	buf[l1] = '.'
	b64.Encode(buf[l1+1:l1+1+l2:l1+1+l2], payload)

	// sign
	sig, err := key.Sign(buf[:l1+1+l2])
	if err != nil {
		return nil, err
	}

	// encode signature to base64
	l3 := b64.EncodedLen(len(sig))
	if len(buf) < l1+l2+l3+2 {
		tmp := make([]byte, l1+l2+l3+2)
		copy(tmp, buf)
		buf = tmp
	} else {
		buf = buf[:l1+l2+l3+2]
	}
	buf[l1+1+l2] = '.'
	b64.Encode(buf[l1+l2+2:], sig)
	return buf, nil
}

func encodeClaims(c *Claims) ([]byte, error) {
	raw := make(map[string]any, len(c.Raw))
	for k, v := range c.Raw {
		raw[k] = v
	}
	e := jsonutils.NewEncoder(raw)

	if iss := c.Issuer; iss != "" {
		e.Set("iss", iss)
	}
	if sub := c.Subject; sub != "" {
		e.Set("sub", sub)
	}
	if aud := c.Audience; aud != nil {
		if len(aud) == 1 {
			e.Set("aud", aud[0])
		} else {
			e.Set("aud", aud)
		}
	}
	if exp := c.ExpirationTime; !exp.IsZero() {
		e.SetTime("exp", exp)
	}
	if nbf := c.NotBefore; !nbf.IsZero() {
		e.SetTime("nbf", nbf)
	}
	if iat := c.IssuedAt; !iat.IsZero() {
		e.SetTime("iat", iat)
	}
	if jti := c.JWTID; jti != "" {
		e.Set("jti", jti)
	}

	if err := e.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(e.Data())
}
