package as

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/crypto"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// HandleCallback handles GET /oauth/callback — the upstream IdP redirect.
func HandleCallback(s *store.Store, oidcMgr *oidc.Manager, cipher *crypto.Cipher, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state") // this is our upstream_state (used as session PK)

	// Handle upstream error responses (e.g. login_required from prompt=none).
	// Per OAuth 2.0 §4.1.2.1 we must forward the error to the original client.
	if upstreamErr := q.Get("error"); upstreamErr != "" {
		// Try to look up the session so we can redirect to the correct client URI.
		if state != "" {
			sess, err := s.GetAuthSession(r.Context(), state)
			if err == nil && sess != nil {
				_ = s.DeleteAuthSession(r.Context(), state)
				clientRedirect, parseErr := url.Parse(sess.RedirectURI)
				if parseErr == nil {
					cq := clientRedirect.Query()
					cq.Set("error", upstreamErr)
					if desc := q.Get("error_description"); desc != "" {
						cq.Set("error_description", desc)
					}
					if sess.OriginalState != "" {
						cq.Set("state", sess.OriginalState)
					}
					clientRedirect.RawQuery = cq.Encode()
					http.Redirect(w, r, clientRedirect.String(), http.StatusFound)
					return
				}
			}
		}
		// Fallback: no session or unparseable redirect_uri — return a generic error.
		writeError(w, http.StatusBadRequest, upstreamErr, q.Get("error_description"))
		return
	}

	if code == "" || state == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code or state")
		return
	}

	// Look up session by upstream_state (which is the PK `state` column).
	sess, err := s.GetAuthSession(r.Context(), state)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up session")
		return
	}
	if sess == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown or expired state")
		return
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteAuthSession(r.Context(), state)
		writeError(w, http.StatusBadRequest, "invalid_request", "session expired")
		return
	}

	// Discover provider.
	provider, err := oidcMgr.Discover(r.Context(), sess.ProviderIssuer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "server_error", "upstream discovery failed: "+err.Error())
		return
	}

	callbackURI := sess.PublicBase + "/oauth/callback"

	// Exchange the upstream code.
	tr, err := oidcMgr.ExchangeCode(r.Context(), provider, rc.ClientID, rc.ClientSecret, code, callbackURI, sess.UpstreamPKCEVerifier)
	if err != nil {
		writeError(w, http.StatusBadGateway, "server_error", "upstream token exchange failed: "+err.Error())
		return
	}

	// Extract user claims from id_token or userinfo.
	var userClaims map[string]any
	if tr.IDToken != "" {
		userClaims, err = oidc.DecodeIDToken(tr.IDToken)
		if err != nil {
			userClaims = map[string]any{}
		}
	} else {
		userClaims, err = oidcMgr.Userinfo(r.Context(), provider, tr.AccessToken)
		if err != nil {
			userClaims = map[string]any{}
		}
	}

	sub, _ := userClaims["sub"].(string)
	if sub == "" {
		sub = "unknown"
	}

	// Keep only safe profile-style claims for the access token.
	// Drop standard JWT claims (we set our own) and ID-Token-specific claims
	// (at_hash, azp, nonce, auth_time, sub) so the minted token doesn't look
	// like an ID Token to RFC 9068-aware clients.
	allowed := map[string]bool{
		"email":              true,
		"email_verified":     true,
		"name":               true,
		"given_name":         true,
		"family_name":        true,
		"picture":            true,
		"locale":             true,
		"hd":                 true,
		"preferred_username": true,
	}
	for k := range userClaims {
		if !allowed[k] {
			delete(userClaims, k)
		}
	}

	claimsJSON, err := json.Marshal(userClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to serialize claims")
		return
	}

	// Encrypt upstream refresh token if present.
	var upstreamRefreshEnc []byte
	if tr.RefreshToken != "" {
		upstreamRefreshEnc, err = cipher.Encrypt([]byte(tr.RefreshToken))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to encrypt refresh token")
			return
		}
	}

	// Generate local code.
	localCodeBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, localCodeBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate local code")
		return
	}
	localCode := base64.RawURLEncoding.EncodeToString(localCodeBytes)

	codeRow := store.Code{
		Code:                localCode,
		ClientID:            sess.ClientID,
		Resource:            sess.Resource,
		Sub:                 sub,
		ClaimsJSON:          string(claimsJSON),
		UpstreamRefreshEnc:  upstreamRefreshEnc,
		Scopes:              sess.Scopes,
		RedirectURI:         sess.RedirectURI,
		CodeChallenge:       sess.CodeChallenge,
		CodeChallengeMethod: sess.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	if err := s.InsertCode(r.Context(), codeRow); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save code")
		return
	}

	// Delete the auth session (single-use).
	_ = s.DeleteAuthSession(r.Context(), state)

	// Redirect back to client.
	clientRedirect, err := url.Parse(sess.RedirectURI)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "invalid redirect_uri in session")
		return
	}
	cq := clientRedirect.Query()
	cq.Set("code", localCode)
	if sess.OriginalState != "" {
		cq.Set("state", sess.OriginalState)
	}
	clientRedirect.RawQuery = cq.Encode()

	http.Redirect(w, r, clientRedirect.String(), http.StatusFound)
}
