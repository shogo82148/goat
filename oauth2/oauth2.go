package oauth2

import (
	"net/http"
	"strings"
)

// ExtractBearer extracts a token from the Authorization request header.
func ExtractBearer(req *http.Request) (bearer string, ok bool) {
	const prefix = "Bearer "
	credentials := req.Header.Get("Authorization")
	if len(credentials) < len(prefix) {
		return "", false
	}

	// RFC 9110 Section 11.1. Authentication Scheme:
	// > It uses a case-insensitive token to identify the authentication scheme:
	// >
	// >     auth-scheme    = token
	// >
	if !strings.EqualFold(credentials[:len(prefix)], prefix) {
		return "", false
	}

	return credentials[len(prefix):], true
}
