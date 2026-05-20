package as

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// HandleAuthorize handles GET /oauth/authorize.
func HandleAuthorize(s *store.Store, oidcMgr *oidc.Manager, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	responseType := q.Get("response_type")
	if responseType != "code" {
		writeError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be 'code'")
		return
	}

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	scope := q.Get("scope")

	slog.Debug("authorize_request",
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"scope", scope,
		"resource_param", q.Get("resource"),
		"has_state", state != "",
		"has_code_challenge", codeChallenge != "",
		"code_challenge_method", codeChallengeMethod,
	)

	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}
	if codeChallengeMethod != "S256" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}

	// Validate client and redirect_uri.
	client, err := s.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}
	if client == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}
	_ = s.TouchClient(r.Context(), client.ClientID)

	var allowedURIs []string
	if err := json.Unmarshal([]byte(client.RedirectURIsJSON), &allowedURIs); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "invalid redirect_uris in client record")
		return
	}
	if !containsString(allowedURIs, redirectURI) {
		writeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
		return
	}

	// Discover upstream provider.
	provider, err := oidcMgr.Discover(r.Context(), rc.ProviderIssuer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "server_error", "upstream discovery failed: "+err.Error())
		return
	}

	// Generate upstream PKCE.
	verifierBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, verifierBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate PKCE verifier")
		return
	}
	upstreamVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	upstreamChallenge := s256Challenge(upstreamVerifier)

	// Generate upstream state.
	upstreamStateBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, upstreamStateBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate upstream state")
		return
	}
	upstreamState := base64.RawURLEncoding.EncodeToString(upstreamStateBytes)

	if scope == "" {
		scope = rc.Scopes
	}

	now := time.Now()
	sess := store.AuthSession{
		State:                upstreamState, // PK is upstream_state
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		RedirectURI:          redirectURI,
		ClientID:             clientID,
		Resource:             rc.Name,
		Scopes:               scope,
		ProviderIssuer:       rc.ProviderIssuer,
		PublicBase:           rc.PublicBase,
		UpstreamState:        upstreamState,
		UpstreamPKCEVerifier: upstreamVerifier,
		OriginalState:        state,
		CreatedAt:            now,
		ExpiresAt:            now.Add(10 * time.Minute),
	}
	if err := s.InsertAuthSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save session")
		return
	}

	// Build upstream redirect URL.
	upstreamURL, err := url.Parse(provider.AuthEndpoint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "invalid upstream auth endpoint")
		return
	}
	uq := url.Values{
		"response_type":         {"code"},
		"client_id":             {rc.ClientID},
		"redirect_uri":          {rc.PublicBase + "/oauth/callback"},
		"scope":                 {rc.Scopes},
		"state":                 {upstreamState},
		"code_challenge":        {upstreamChallenge},
		"code_challenge_method": {"S256"},
	}
	// Forward prompt parameter to upstream IdP so that prompt=none is honoured.
	if prompt := q.Get("prompt"); prompt != "" {
		uq.Set("prompt", prompt)
	}
	upstreamURL.RawQuery = uq.Encode()

	http.Redirect(w, r, upstreamURL.String(), http.StatusFound)
}

// s256Challenge computes the PKCE S256 code challenge from a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
