package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jws"
)

var nowFunc = time.Now // for testing

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

// Token is a decoded JWT token.
type Token struct {
	Header *jws.Header
	Claims *Claims
}

func Parse(ctx context.Context, data []byte, finder jws.KeyFinder) (*Token, error) {
	msg, err := jws.Parse(ctx, data, finder)
	if err != nil {
		return nil, err
	}
	c, err := parseClaims(msg.Payload)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Header: msg.Header,
		Claims: c,
	}
	return token, nil
}

func parseClaims(data []byte) (*Claims, error) {
	now := nowFunc()

	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("jwt: failed to parse claims: %w", err)
	}
	c := &Claims{
		Raw: raw,
	}
	d := jsonutils.NewDecoder("jwt", raw)

	c.Issuer, _ = d.GetString("iss")
	c.Subject, _ = d.GetString("sub")
	c.Audience, _ = d.GetString("aud")

	if t, ok := d.GetTime("exp"); ok {
		c.ExpirationTime = t
		if !now.Before(t) {
			d.NewError(fmt.Errorf("jwt: token is expired"))
		}
	}

	if t, ok := d.GetTime("nbf"); ok {
		c.NotBefore = t
		if now.Before(t) {
			d.NewError(fmt.Errorf("jwt: token is not valid yet"))
		}
	}

	c.IssuedAt, _ = d.GetTime("iat")
	c.JWTID, _ = d.GetString("jti")

	if err := d.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
