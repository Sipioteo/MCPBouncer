package as

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/crypto"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

// HandleToken handles POST /oauth/token.
func HandleToken(s *store.Store, oidcMgr *oidc.Manager, issuer *tokens.Issuer, cipher *crypto.Cipher, rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
		return
	}

	grantType := r.FormValue("grant_type")

	slog.Info("token_request",
		"grant_type", grantType,
		"client_id_form", r.FormValue("client_id"),
		"has_basic_auth", r.Header.Get("Authorization") != "",
		"has_code", r.FormValue("code") != "",
		"has_code_verifier", r.FormValue("code_verifier") != "",
		"has_refresh_token", r.FormValue("refresh_token") != "",
		"redirect_uri", r.FormValue("redirect_uri"),
	)

	// Authenticate client.
	clientID, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	client, err := s.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}
	if client == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}

	// Verify secret if provided (skip for public clients sending only client_id).
	if clientSecret != "" {
		if sha256Hex(clientSecret) != client.ClientSecretHash {
			writeError(w, http.StatusUnauthorized, "invalid_client", "invalid client_secret")
			return
		}
	}

	switch grantType {
	case "authorization_code":
		handleAuthorizationCode(s, issuer, cipher, rc, client, w, r)
	case "refresh_token":
		handleRefreshToken(s, oidcMgr, issuer, cipher, rc, client, w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type: "+grantType)
	}
}

func handleAuthorizationCode(s *store.Store, issuer *tokens.Issuer, cipher *crypto.Cipher, rc *config.ResourceConfig, client *store.Client, w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || codeVerifier == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code, redirect_uri, or code_verifier")
		return
	}

	codeRow, err := s.GetCode(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up code")
		return
	}
	if codeRow == nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", "unknown or already used code")
		return
	}

	// Single-use: delete immediately.
	_ = s.DeleteCode(r.Context(), code)

	if codeRow.ClientID != client.ClientID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code does not belong to this client")
		return
	}
	if codeRow.RedirectURI != redirectURI {
		writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if time.Now().After(codeRow.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}

	// Verify PKCE.
	if codeRow.CodeChallengeMethod == "S256" {
		computed := pkceS256Challenge(codeVerifier)
		if computed != codeRow.CodeChallenge {
			writeError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match code_challenge")
			return
		}
	}

	// Parse extra claims.
	var extraClaims map[string]any
	if codeRow.ClaimsJSON != "" {
		_ = json.Unmarshal([]byte(codeRow.ClaimsJSON), &extraClaims)
	}
	if extraClaims == nil {
		extraClaims = map[string]any{}
	}

	// Mint access token.
	accessToken, _, err := issuer.MintAccessToken(r.Context(), rc, codeRow.Sub, codeRow.Scopes, codeRow.ClientID, extraClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to mint access token: "+err.Error())
		return
	}

	// Mint refresh token.
	rawRefresh, refreshHash, refreshExpiry, err := issuer.MintRefreshToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to mint refresh token")
		return
	}

	rt := store.RefreshToken{
		TokenHash:          refreshHash,
		Sub:                codeRow.Sub,
		Resource:           codeRow.Resource,
		ClientID:           codeRow.ClientID,
		UpstreamRefreshEnc: codeRow.UpstreamRefreshEnc,
		Scopes:             codeRow.Scopes,
		ExpiresAt:          refreshExpiry,
	}
	if err := s.InsertRefreshToken(r.Context(), rt); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save refresh token")
		return
	}

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(issuer.AccessTTL().Seconds()),
		"refresh_token": rawRefresh,
		"scope":         codeRow.Scopes,
	}
	respBytes, _ := json.Marshal(resp)
	slog.Info("token_response", "body", string(respBytes))
	writeJSON(w, http.StatusOK, resp)
}

func handleRefreshToken(s *store.Store, oidcMgr *oidc.Manager, issuer *tokens.Issuer, cipher *crypto.Cipher, rc *config.ResourceConfig, client *store.Client, w http.ResponseWriter, r *http.Request) {
	rawRefresh := r.FormValue("refresh_token")
	if rawRefresh == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	hash := tokens.HashToken(rawRefresh)
	rt, err := s.GetRefreshTokenByHash(r.Context(), hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to look up refresh token")
		return
	}
	if rt == nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", "unknown or already used refresh token")
		return
	}

	// Rotate: delete immediately.
	_ = s.DeleteRefreshTokenByHash(r.Context(), hash)

	if rt.ClientID != client.ClientID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token does not belong to this client")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	// Optionally refresh upstream tokens.
	upstreamRefreshEnc := rt.UpstreamRefreshEnc
	if len(upstreamRefreshEnc) > 0 && oidcMgr != nil {
		if plain, err := cipher.Decrypt(upstreamRefreshEnc); err == nil {
			provider, err := oidcMgr.Discover(r.Context(), rc.ProviderIssuer)
			if err == nil {
				upstreamResp, err := oidcMgr.RefreshTokens(r.Context(), provider, rc.ClientID, rc.ClientSecret, string(plain))
				if err == nil && upstreamResp.RefreshToken != "" {
					if enc, err := cipher.Encrypt([]byte(upstreamResp.RefreshToken)); err == nil {
						upstreamRefreshEnc = enc
					}
				}
			}
		}
	}

	// Mint new local access + refresh.
	var extraClaims map[string]any // we don't re-fetch userinfo on refresh for simplicity

	accessToken, _, err := issuer.MintAccessToken(r.Context(), rc, rt.Sub, rt.Scopes, rt.ClientID, extraClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to mint access token")
		return
	}

	newRawRefresh, newHash, newExpiry, err := issuer.MintRefreshToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to mint refresh token")
		return
	}

	newRT := store.RefreshToken{
		TokenHash:          newHash,
		Sub:                rt.Sub,
		Resource:           rt.Resource,
		ClientID:           rt.ClientID,
		UpstreamRefreshEnc: upstreamRefreshEnc,
		Scopes:             rt.Scopes,
		ExpiresAt:          newExpiry,
	}
	if err := s.InsertRefreshToken(r.Context(), newRT); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save new refresh token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(issuer.AccessTTL().Seconds()),
		"refresh_token": newRawRefresh,
		"scope":         rt.Scopes,
	})
}

// extractClientCredentials reads client_id and client_secret from POST body or Basic auth.
func extractClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	// Try POST body first.
	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")
	if clientID != "" {
		return clientID, clientSecret, nil
	}

	// Fall back to Basic auth.
	u, p, ok := r.BasicAuth()
	if ok && u != "" {
		return u, p, nil
	}

	return "", "", fmt.Errorf("no client credentials provided")
}

// pkceS256Challenge computes the PKCE S256 challenge from a verifier.
func pkceS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
