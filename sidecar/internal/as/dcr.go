package as

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// schemeRe matches valid URI scheme syntax (RFC 3986).
var schemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.\-]*$`)

// schemeDenylist contains schemes that are always rejected.
var schemeDenylist = map[string]bool{
	"javascript": true,
	"data":       true,
	"file":       true,
	"vbscript":   true,
	"blob":       true,
	"about":      true,
}

// validateRedirectURI returns an error description if the URI is not allowed,
// or an empty string if it is valid.
func validateRedirectURI(raw string) string {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "invalid redirect_uri: " + raw
	}
	scheme := parsed.Scheme
	if schemeDenylist[scheme] {
		return "redirect_uri scheme not allowed: " + scheme
	}
	switch scheme {
	case "https", "mcp":
		// always allowed
	case "http":
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return "http redirect_uri only allowed for localhost or 127.0.0.1, got: " + raw
		}
	default:
		if !schemeRe.MatchString(scheme) {
			return "redirect_uri has invalid scheme: " + scheme
		}
	}
	return ""
}

type registerRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
}

// HandleRegister handles POST /oauth/register (RFC 7591 Dynamic Client Registration).
func HandleRegister(s *store.Store, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	// Optional Initial Access Token guard (RFC 7591 §3).
	if initialToken := os.Getenv("BOUNCER_DCR_INITIAL_TOKEN"); initialToken != "" {
		const prefix = "Bearer "
		authHeader := r.Header.Get("Authorization")
		var provided string
		if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
			provided = authHeader[len(prefix):]
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(initialToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid_token", "valid Bearer token required for registration")
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "cannot read body")
		return
	}

	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri required")
		return
	}
	for _, ru := range req.RedirectURIs {
		if desc := validateRedirectURI(ru); desc != "" {
			writeError(w, http.StatusBadRequest, "invalid_redirect_uri", desc)
			return
		}
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	// Generate credentials.
	clientID, err := randomHex(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate client_id")
		return
	}

	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate secret")
		return
	}
	clientSecret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := sha256Hex(clientSecret)

	ratBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ratBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate registration_access_token")
		return
	}
	rat := base64.RawURLEncoding.EncodeToString(ratBytes)
	ratHash := sha256Hex(rat)

	// Serialize redirect_uris.
	redirectURIsJSON, err := json.Marshal(req.RedirectURIs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to serialize redirect_uris")
		return
	}

	scope := req.Scope
	if scope == "" {
		scope = rc.Scopes
	}

	client := store.Client{
		ClientID:                    clientID,
		ClientSecretHash:            secretHash,
		RedirectURIsJSON:            string(redirectURIsJSON),
		RegistrationAccessTokenHash: ratHash,
		Resource:                    rc.Name,
		Scopes:                      scope,
		CreatedAt:                   time.Now(),
	}
	if err := s.InsertClient(r.Context(), client); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to persist client")
		return
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"client_secret_expires_at":   0,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_method": "client_secret_post",
		"registration_access_token":  rat,
		"registration_client_uri":    rc.PublicBase + "/oauth/register/" + clientID,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
