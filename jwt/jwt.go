// Package jws handles JSON Web Token defined in RFC 7519.
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

var b64 = base64.RawURLEncoding
var nowFunc = time.Now // for testing

// Claims is a JWT Claims Set defined in RFC7519.
type Claims struct {
	// RFC7519 Section 4.1.1. "iss" (Issuer) Claim
	Issuer string

	// RFC7519 Section 4.1.2. "sub" (Subject) Claim
	Subject string

	// RFC7519 Section 4.1.3. "aud" (Audience) Claim
	Audience []string

	// RFC7519 Section 4.1.4. "exp" (Expiration Time) Claim
	ExpirationTime time.Time

	// RFC7519 Section 4.1.5. "nbf" (Not Before) Claim
	NotBefore time.Time

	// RFC7519 Section 4.1.6. "iat" (Issued At) Claim
	IssuedAt time.Time

	// RFC7519 Section 4.1.7. "jti" (JWT ID) Claim
	JWTID string

	// Raw is the raw data of JSON-decoded JOSE header.
	// JSON numbers are decoded as json.Number to avoid data loss.
	Raw map[string]any
}

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	FindKey(header *jws.Header) (key sig.SigningKey, err error)
}

type FindKeyFunc func(header *jws.Header) (key sig.SigningKey, err error)

func (f FindKeyFunc) FindKey(header *jws.Header) (key sig.SigningKey, err error) {
	return f(header)
}

// Token is a decoded JWT token.
type Token struct {
	Header *jws.Header
	Claims *Claims
}

func Parse(data []byte, finder KeyFinder) (*Token, error) {
	// split to segments
	idx1 := bytes.IndexByte(data, '.')
	if idx1 < 0 {
		return nil, errors.New("jwt: failed to parse: invalid format")
	}
	idx2 := bytes.IndexByte(data[idx1+1:], '.')
	if idx2 < 0 {
		return nil, errors.New("jwt: failed to parse: invalid format")
	}
	idx2 += idx1 + 1
	b64header := data[:idx1]
	b64payload := data[idx1+1 : idx2]
	b64signature := data[idx2+1:]

	// pre-allocate buffer
	size := len(b64header)
	if len(b64payload) > size {
		size = len(b64payload)
	}
	if len(b64signature) > size {
		size = len(b64signature)
	}
	buf := make([]byte, b64.DecodedLen(size))

	// parse header
	n, err := b64.Decode(buf[:cap(buf)], b64header)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to parse header: %w", err)
	}
	buf = buf[:n]
	var header jws.Header
	if header.UnmarshalJSON(buf[:n]) != nil {
		return nil, fmt.Errorf("jwt: failed to parse header: %w", err)
	}

	// verify signature
	key, err := finder.FindKey(&header)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to find key: %w", err)
	}
	n, err = b64.Decode(buf[:cap(buf)], b64signature)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to parse signature: %w", err)
	}
	buf = buf[:n]
	if err := key.Verify(data[:idx2], buf[:n]); err != nil {
		return nil, fmt.Errorf("jwt: failed to verify signature: %w", err)
	}

	// parse payload
	n, err = b64.Decode(buf[:cap(buf)], b64payload)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to parse signature: %w", err)
	}
	buf = buf[:n]

	c, err := parseClaims(buf)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Header: &header,
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

	// In RFC7519, the "aud" claim is defined as a string or an array of strings.
	if aud, ok := raw["aud"]; ok {
		switch aud := aud.(type) {
		case []any:
			for _, v := range aud {
				s, ok := v.(string)
				if !ok {
					d.SaveError(fmt.Errorf("jwt: invalid type of aud claim: %T", v))
				}
				c.Audience = append(c.Audience, s)
			}
		case string:
			c.Audience = []string{aud}
		}
	}

	if t, ok := d.GetTime("exp"); ok {
		c.ExpirationTime = t
		if !now.Before(t) {
			d.SaveError(fmt.Errorf("jwt: token is expired"))
		}
	}

	if t, ok := d.GetTime("nbf"); ok {
		c.NotBefore = t
		if now.Before(t) {
			d.SaveError(fmt.Errorf("jwt: token is not valid yet"))
		}
	}

	c.IssuedAt, _ = d.GetTime("iat")
	c.JWTID, _ = d.GetString("jti")

	if err := d.Err(); err != nil {
		return nil, err
	}
	return c, nil
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
