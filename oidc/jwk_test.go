package oidc

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestGetJWKS(t *testing.T) {
	for _, platform := range platforms {
		testJWKS(t, platform)
	}
}

func testJWKS(t *testing.T, platform string) {
	ctx := t.Context()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected http method: want %s, got %s", http.MethodGet, r.Method)
		}
		if got, want := r.URL.Path, "/.well-known/jwks"; got != want {
			t.Errorf("unexpected path: want %q, got %q", want, got)
		}
		http.ServeFile(rw, r, filepath.Join("testdata", platform+"-jwks.json"))
	}))
	defer ts.Close()

	c, err := NewClient(&ClientConfig{
		Doer:   ts.Client(),
		Issuer: ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := c.GetJWKSFromURL(ctx, ts.URL+"/.well-known/jwks")
	if err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) == 0 {
		t.Errorf("%s: empty JWKS", platform)
	}
}
