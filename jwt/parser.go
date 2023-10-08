package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/internal/jsonutils"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/sig"
)

// KeyFinder finds the key used for signing.
// e.g, you can return a key corresponding to the KID.
type KeyFinder interface {
	FindKey(ctx context.Context, header *jws.Header) (key sig.SigningKey, err error)
}

// FindKeyFunc is an adapter to allow the use of ordinary functions as KeyFinder interfaces.
// If f is a function with the appropriate signature, FindKeyFunc(f) is a KeyFinder that calls f.
type FindKeyFunc func(ctx context.Context, header *jws.Header) (key sig.SigningKey, err error)

// FindKey calls f(header).
func (f FindKeyFunc) FindKey(ctx context.Context, header *jws.Header) (sig.SigningKey, error) {
	return f(ctx, header)
}

// AlgorithmVerfier verifies the algorithm used for signing.
type AlgorithmVerfier interface {
	VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error
}

// UnsecureAnyAlgorithm is an AlgorithmVerfier that accepts any algorithm.
var UnsecureAnyAlgorithm = unsecureAnyAlgorithmVerifier{}

type unsecureAnyAlgorithmVerifier struct{}

func (unsecureAnyAlgorithmVerifier) VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error {
	return nil
}

// AllowedAlgorithms is an AlgorithmVerfier that accepts only the specified algorithms.
type AllowedAlgorithms []jwa.SignatureAlgorithm

func (a AllowedAlgorithms) VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error {
	for _, allowed := range a {
		if alg == allowed {
			return nil
		}
	}
	return errors.New("jwt: signing algorithm is not allowed")
}

// IssuerSubjectVerifier verifies the issuer and the subject.
type IssuerSubjectVerifier interface {
	VerifyIssuer(ctx context.Context, iss, sub string) error
}

// Issuer is a verifier that accepts only the specified issuer.
type Issuer string

func (i Issuer) VerifyIssuer(ctx context.Context, iss, sub string) error {
	if iss != string(i) {
		return fmt.Errorf("jwt: invalid issuer: %s", iss)
	}
	return nil
}

// UnsecureAnyIssuerSubject is an IssuerSubjectVerifier that accepts any issuer and subject.
// This is not recommended.
var UnsecureAnyIssuerSubject = unsecureAnyIssuerSubjectVerifier{}

type unsecureAnyIssuerSubjectVerifier struct{}

func (unsecureAnyIssuerSubjectVerifier) VerifyIssuer(ctx context.Context, iss, sub string) error {
	return nil
}

// AudienceVerifier verifies the audience.
type AudienceVerifier interface {
	VerifyAudience(ctx context.Context, aud []string) error
}

var UnsecureAnyAudience = unsecureAnyAudienceVerifier{}

type unsecureAnyAudienceVerifier struct{}

func (unsecureAnyAudienceVerifier) VerifyAudience(ctx context.Context, aud []string) error {
	return nil
}

// Parser is a JWT parser.
type Parser struct {
	_NamedFieldsRequired struct{}

	KeyFinder             KeyFinder
	AlgorithmVerfier      AlgorithmVerfier
	IssuerSubjectVerifier IssuerSubjectVerifier
	AudienceVerifier      AudienceVerifier
}

func (p *Parser) Parse(ctx context.Context, data []byte) (*Token, error) {
	// verify the parser options
	_ = p._NamedFieldsRequired
	if p.KeyFinder == nil || p.AlgorithmVerfier == nil || p.IssuerSubjectVerifier == nil || p.AudienceVerifier == nil {
		return nil, errors.New("jwt: parser is not configured")
	}

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
	key, err := p.KeyFinder.FindKey(ctx, &header)
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

	// parse claims
	c, err := p.parseClaims(ctx, buf)
	if err != nil {
		return nil, err
	}
	token := &Token{
		Header: &header,
		Claims: c,
	}
	return token, nil
}

func (p *Parser) parseClaims(ctx context.Context, data []byte) (*Claims, error) {
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
	if err := p.IssuerSubjectVerifier.VerifyIssuer(ctx, c.Issuer, c.Subject); err != nil {
		return nil, fmt.Errorf("jwt: failed to verify issuer and subject: %w", err)
	}

	// In RFC 7519, the "aud" claim is defined as a string or an array of strings.
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
	if err := p.AudienceVerifier.VerifyAudience(ctx, c.Audience); err != nil {
		return nil, fmt.Errorf("jwt: failed to verify audience: %w", err)
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
