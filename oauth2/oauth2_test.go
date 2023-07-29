package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractBearer(t *testing.T) {
	tests := []struct {
		in  string
		out string
		ok  bool
	}{
		{
			in:  "Bearer some-token",
			out: "some-token",
			ok:  true,
		},
		{
			in: "",
			ok: false,
		},
		{
			in: "Bearer",
			ok: false,
		},
		{
			in: "bearer some-token",
			ok: false,
		},
		{
			in: "bearer",
			ok: false,
		},
		{
			in: "token some-token",
			ok: false,
		},
	}

	for i, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", tt.in)
		got, ok := ExtractBearer(req)
		if ok != tt.ok {
			t.Errorf("%d: got %t, want %t", i, ok, tt.ok)
		}
		if got != tt.out {
			t.Errorf("%d: got %s, want %s", i, got, tt.out)
		}
	}
}
