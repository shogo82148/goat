package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shogo82148/goat/jwa"
)

// Config is OpenID Provider Metadata defined in [OpenID Connect Discovery 1.0].
//
// [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
type Config struct {
	Issuer                                     string                       `json:"issuer,omitempty"`
	AuthorizationEndpoint                      string                       `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string                       `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           string                       `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                    string                       `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                       string                       `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string                     `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string                     `json:"response_types_supported,omitempty"`
	GrantTypesSupported                        []string                     `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                         []string                     `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string                     `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []jwa.SignatureAlgorithm     `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValuesSupported        []jwa.KeyManagementAlgorithm `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported        []jwa.EncryptionAlgorithm    `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []jwa.SignatureAlgorithm     `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []jwa.KeyManagementAlgorithm `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []jwa.EncryptionAlgorithm    `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []jwa.SignatureAlgorithm     `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []jwa.KeyManagementAlgorithm `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []jwa.SignatureAlgorithm     `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string                     `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string                     `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string                     `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string                     `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string                     `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string                       `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string                     `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                         []string                     `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool                         `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  bool                         `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported               bool                         `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration              bool                         `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                string                       `json:"op_policy_uri,omitempty"`
	OPTOSURI                                   string                       `json:"op_tos_uri,omitempty"`
}

// GetConfig get the OpenID Provider configuration from the issuer.
func (c *Client) GetConfig(ctx context.Context) (*Config, error) {
	prefix := strings.TrimSuffix(c.issuer, "/") // remove trailing '/'
	configURL := prefix + "/.well-known/openid-configuration"
	config, _, err := c.oidcConfig.Do(ctx, configURL, c.getConfig)
	return config, err
}

func (c *Client) getConfig(ctx context.Context, configURL string) (*Config, time.Time, error) {
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

	// build the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	// send the request
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
	}

	// parse the response body
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, err
	}
	var config Config
	if err := json.Unmarshal(buf, &config); err != nil {
		return nil, time.Time{}, err
	}
	return &config, expiresAt, nil
}
