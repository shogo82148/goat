package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var platforms = []string{
	"gha",
	"google",
	"microsoft",
	"facebook",
	"apple",
	"yahoo",
	"line",
	"recruit",
	"slack",
	"paypal",
	"firebase",
	"nikkei",
	"gitlab",
	"okta",
}

func TestConfig(t *testing.T) {
	for _, platform := range platforms {
		data, err := os.ReadFile(filepath.Join("testdata", fmt.Sprintf("%s-openid-configuration.json", platform)))
		if err != nil {
			t.Fatal(err)
		}

		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Errorf("%s: failed to parse openid-configuration: %v", platform, err)
		}
	}
}
