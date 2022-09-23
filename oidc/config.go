package oidc

import "github.com/shogo82148/goat/jwa"

// Config is OpenID Provider Metadata defined in [OpenID Connect Discovery 1.0].
//
// [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
type Config struct {
	Issuer                                     string                   `json:"issuer,omitempty"`
	AuthorizationEndpoint                      string                   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string                   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           string                   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                    string                   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                       string                   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string                 `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string                 `json:"response_types_supported,omitempty"`
	GrantTypesSupported                        []string                 `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                         []string                 `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string                 `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []jwa.SignatureAlgorithm `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValuesSupported        []string                 `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported        []string                 `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []jwa.SignatureAlgorithm `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string                 `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string                 `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []jwa.SignatureAlgorithm `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string                 `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string                 `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string                 `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string                 `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string                 `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string                 `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string                 `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string                   `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string                 `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                         []string                 `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool                     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  bool                     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported               bool                     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration              bool                     `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                string                   `json:"op_policy_uri,omitempty"`
	OPTOSURI                                   string                   `json:"op_tos_uri,omitempty"`
}
