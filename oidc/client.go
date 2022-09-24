package oidc

import (
	"net/http"

	"github.com/shogo82148/goat/jwk"
	"github.com/shogo82148/memoize"
)

const (
	// The default value of User-Agent header
	defaultUserAgent = "https://github.com/shogo82148/goat"
)

// Doer is a interface for doing an http request, such as http.Client.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ClientConfig is configure for client.
type ClientConfig struct {
	// Doer is used for http requests.
	// If it nil, http.DefaultClient is used.
	Doer Doer

	// UserAgent is the value of User-Agent header in http requests.
	// If it is empty string, "https://github.com/shogo82148/goat" is used.
	UserAgent string

	// Issuer is the issuer.
	Issuer string
}

// Client a client for fetching the OpenID Provider configuration.
type Client struct {
	doer      Doer
	issuer    string
	userAgent string

	oidcConfig memoize.Group[string, *Config]
	jwks       memoize.Group[string, *jwk.Set]
}

// NewClient returns a new client.
func NewClient(config *ClientConfig) (*Client, error) {
	doer := config.Doer
	if doer == nil {
		doer = http.DefaultClient
	}
	issuer := config.Issuer
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	return &Client{
		doer:      doer,
		issuer:    issuer,
		userAgent: userAgent,
	}, nil
}
