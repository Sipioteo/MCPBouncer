package as

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sipiote/mcpbouncer-sidecar/internal/config"
)

// HandleProtectedResource serves RFC 9728 oauth-protected-resource metadata.
func HandleProtectedResource(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	var scopes []string
	for _, s := range strings.Fields(rc.Scopes) {
		scopes = append(scopes, s)
	}
	body := map[string]any{
		"resource":                  rc.PublicBase,
		"authorization_servers":     []string{rc.PublicBase},
		"bearer_methods_supported":  []string{"header"},
		"scopes_supported":          scopes,
		"resource_documentation":    "https://github.com/sipiote/mcpbouncer",
	}
	writeJSON(w, http.StatusOK, body)
}

// HandleAuthorizationServer serves RFC 8414 oauth-authorization-server metadata.
func HandleAuthorizationServer(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	var scopes []string
	for _, s := range strings.Fields(rc.Scopes) {
		scopes = append(scopes, s)
	}
	body := map[string]any{
		"issuer":                                rc.PublicBase,
		"authorization_endpoint":                rc.PublicBase + "/oauth/authorize",
		"token_endpoint":                        rc.PublicBase + "/oauth/token",
		"registration_endpoint":                 rc.PublicBase + "/oauth/register",
		"jwks_uri":                              rc.PublicBase + "/oauth/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      scopes,
		"service_documentation":                 "https://github.com/sipiote/mcpbouncer",
	}
	writeJSON(w, http.StatusOK, body)
}

// HandleOpenIDConfiguration serves the openid-configuration alias with extra OIDC fields.
func HandleOpenIDConfiguration(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	var scopes []string
	for _, s := range strings.Fields(rc.Scopes) {
		scopes = append(scopes, s)
	}
	body := map[string]any{
		"issuer":                                rc.PublicBase,
		"authorization_endpoint":                rc.PublicBase + "/oauth/authorize",
		"token_endpoint":                        rc.PublicBase + "/oauth/token",
		"registration_endpoint":                 rc.PublicBase + "/oauth/register",
		"jwks_uri":                              rc.PublicBase + "/oauth/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      scopes,
		"service_documentation":                 "https://github.com/sipiote/mcpbouncer",
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
	}
	writeJSON(w, http.StatusOK, body)
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
