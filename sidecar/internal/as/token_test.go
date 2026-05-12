package as_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

func insertTestCode(t *testing.T, s *store.Store, codeVal, clientID, redirectURI, challenge, verifierForChallenge string) {
	t.Helper()
	codeRow := store.Code{
		Code:                codeVal,
		ClientID:            clientID,
		Resource:            "wiki",
		Sub:                 "testuser",
		ClaimsJSON:          `{"email":"testuser@example.com"}`,
		UpstreamRefreshEnc:  nil,
		Scopes:              "openid email",
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	if err := s.InsertCode(context.Background(), codeRow); err != nil {
		t.Fatalf("InsertCode: %v", err)
	}
}

func TestHandleToken_AuthorizationCode(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	verifier := "my-pkce-verifier-long-enough-32b"
	challenge := s256(verifier)
	insertTestCode(t, deps.store, "mycode123", "test-client-id", "https://client.example.com/callback", challenge, verifier)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"mycode123"},
		"redirect_uri":  {"https://client.example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	accessToken, ok := resp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("expected non-empty access_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp["token_type"])
	}
	if resp["refresh_token"] == "" {
		t.Errorf("expected non-empty refresh_token")
	}

	// Decode JWT header and verify kid is present.
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse JWT header: %v", err)
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", header["alg"])
	}
	if header["kid"] == "" {
		t.Errorf("expected non-empty kid in JWT header")
	}

	// Code must be single-use.
	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"mycode123"},
		"redirect_uri":  {"https://client.example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("second use of code: expected 400, got %d", rr2.Code)
	}
}

func TestHandleToken_PKCEMismatch(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	verifier := "correct-pkce-verifier-padded-32b"
	challenge := s256(verifier)
	insertTestCode(t, deps.store, "mismatch-code", "test-client-id", "https://client.example.com/callback", challenge, verifier)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"mismatch-code"},
		"redirect_uri":  {"https://client.example.com/callback"},
		"code_verifier": {"wrong-verifier"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for PKCE mismatch, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleToken_RefreshFlow(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	// Create a refresh token in the store.
	rawRT, hashRT, expiry, err := deps.issuer.MintRefreshToken()
	if err != nil {
		t.Fatalf("MintRefreshToken: %v", err)
	}
	rt := store.RefreshToken{
		TokenHash: hashRT,
		Sub:       "testuser",
		Resource:  deps.rc.Name,
		ClientID:  "test-client-id",
		Scopes:    "openid email",
		ExpiresAt: expiry,
	}
	if err := deps.store.InsertRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawRT},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["access_token"] == "" {
		t.Errorf("expected access_token")
	}
	newRT, ok := resp["refresh_token"].(string)
	if !ok || newRT == "" {
		t.Errorf("expected new refresh_token")
	}
	if newRT == rawRT {
		t.Errorf("new refresh_token should differ from old (token rotation)")
	}

	// Old refresh token must be gone.
	old, err := deps.store.GetRefreshTokenByHash(context.Background(), tokens.HashToken(rawRT))
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if old != nil {
		t.Errorf("old refresh token should have been deleted")
	}
}
