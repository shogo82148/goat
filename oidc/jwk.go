package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/shogo82148/goat/jwk"
)

// GetJWKS gets JWKS (JSON Web Key Set).
// GetJWKS uses the OpenID Provider configuration for getting the url of JWKS.
func (c *Client) GetJWKS(ctx context.Context) (*jwk.Set, error) {
	cfg, err := c.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetJWKSFromURL(ctx, cfg.JWKSURI)
}

// GetJWKSFromURL gets JWKS (JSON Web Key Set) from url.
func (c *Client) GetJWKSFromURL(ctx context.Context, url string) (*jwk.Set, error) {
	set, _, err := c.jwks.Do(ctx, url, c.getJWKS)
	return set, err
}

func (c *Client) getJWKS(ctx context.Context, url string) (*jwk.Set, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// some providers, such as GitHub Actions, returns "cache-control: no-store,no-cache".
	// but I think I can cache them.
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	// The monotonic clock reading can be incorrect in cases where the host system is hibernated
	// (for example using EC2 Hibernate, AWS Lambda, etc).
	// So convert it to wall-clock.
	expiresAt = expiresAt.Round(0)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/jwk-set+json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, err
	}

	set, err := jwk.ParseSet(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	return set, expiresAt, nil
}
