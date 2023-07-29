package oauth2

import (
	"net/http"
	"strings"
)

// ExtractBearer extracts a token from the Authorization request header.
func ExtractBearer(req *http.Request) (bearer string, ok bool) {
	const prefix = "Bearer "
	credentials := req.Header.Get("Authorization")

	// RFC 6750 says "Unless otherwise noted, all the protocol
	// parameter names and values are case sensitive."
	if !strings.HasPrefix(credentials, prefix) {
		return "", false
	}

	return credentials[len(prefix):], true
}
