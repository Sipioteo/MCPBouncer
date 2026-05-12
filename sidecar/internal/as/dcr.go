package as

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

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
		parsed, err := url.ParseRequestURI(ru)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid_redirect_uri", "invalid redirect_uri: "+ru)
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
		"client_id":                   clientID,
		"client_secret":               clientSecret,
		"client_secret_expires_at":    0,
		"redirect_uris":               req.RedirectURIs,
		"grant_types":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_method":  "client_secret_post",
		"registration_access_token":   rat,
		"registration_client_uri":     rc.PublicBase + "/oauth/register/" + clientID,
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
