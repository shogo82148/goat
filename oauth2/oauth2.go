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

	// RFC 6750 says "Unless otherwise noted, all the protocol
	// parameter names and values are case sensitive.",
	// so "Bearer" should be case sensitive.
	// However some clients sends "bearer", and we accept them.
	if !strings.EqualFold(credentials[:len(prefix)], prefix) {
		return "", false
	}

	return credentials[len(prefix):], true
}
