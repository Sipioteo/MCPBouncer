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

// insertTestClientWithSecret inserts a client with the given secret hash (or no
// secret when secretHash is empty).
func insertTestClientWithSecret(t *testing.T, s *store.Store, clientID, secretHash string, redirectURIs []string, resource string) {
	t.Helper()
	urisJSON, _ := json.Marshal(redirectURIs)
	c := store.Client{
		ClientID:                    clientID,
		ClientSecretHash:            secretHash,
		RedirectURIsJSON:            string(urisJSON),
		RegistrationAccessTokenHash: hexSHA256("test-rat-" + clientID),
		Resource:                    resource,
		Scopes:                      "openid email profile",
		CreatedAt:                   time.Now(),
	}
	if err := s.InsertClient(context.Background(), c); err != nil {
		t.Fatalf("InsertClient: %v", err)
	}
}

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
		TokenHash:  hashRT,
		Sub:        "testuser",
		Resource:   deps.rc.Name,
		ClientID:   "test-client-id",
		ClaimsJSON: `{"email":"testuser@example.com","name":"Test User"}`,
		Scopes:     "openid email",
		ExpiresAt:  expiry,
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

	// Identity claims must survive the refresh and ride into the new access token.
	at, _ := resp["access_token"].(string)
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		t.Fatalf("access_token is not a JWT: %q", at)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal access_token claims: %v", err)
	}
	if got := claims["email"]; got != "testuser@example.com" {
		t.Errorf("refreshed access_token lost email claim; got %v", got)
	}
	if got := claims["name"]; got != "Test User" {
		t.Errorf("refreshed access_token lost name claim; got %v", got)
	}

	// And the rotated refresh token must keep the claims for the next cycle.
	persisted, err := deps.store.GetRefreshTokenByHash(context.Background(), tokens.HashToken(newRT))
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash(new): %v", err)
	}
	if persisted == nil || !strings.Contains(persisted.ClaimsJSON, "testuser@example.com") {
		t.Errorf("rotated refresh token did not persist claims; got %+v", persisted)
	}
}

// TestHandleToken_MissingSecret_ConfidentialClient verifies that a confidential
// client (ClientSecretHash != "") that sends no client_secret is rejected 401.
func TestHandleToken_MissingSecret_ConfidentialClient(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	// Insert a confidential client (has a secret hash).
	insertTestClientWithSecret(t, deps.store, "secret-client-id", hexSHA256("supersecret"),
		[]string{"https://client.example.com/callback"}, deps.rc.Name)

	verifier := "pkce-verifier-long-enough-32bytes"
	challenge := s256(verifier)
	insertTestCode(t, deps.store, "secret-code", "secret-client-id", "https://client.example.com/callback", challenge, verifier)

	// Request omits client_secret entirely.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"secret-code"},
		"redirect_uri":  {"https://client.example.com/callback"},
		"code_verifier": {verifier},
		"client_id":     {"secret-client-id"},
		// no client_secret
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when client_secret omitted for confidential client, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401 response")
	}
	var errResp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_client" {
		t.Errorf("expected error=invalid_client, got %q", errResp["error"])
	}
}

// TestHandleToken_PKCEUnsupportedMethod verifies that a code stored with a
// method other than S256 (e.g. "plain" or empty) is rejected with invalid_grant.
func TestHandleToken_PKCEUnsupportedMethod(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	// Insert a code whose CodeChallengeMethod is not S256.
	plainCode := store.Code{
		Code:                "plain-pkce-code",
		ClientID:            "test-client-id",
		Resource:            "wiki",
		Sub:                 "testuser",
		ClaimsJSON:          `{}`,
		Scopes:              "openid",
		RedirectURI:         "https://client.example.com/callback",
		CodeChallenge:       "some-challenge",
		CodeChallengeMethod: "plain",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	if err := deps.store.InsertCode(context.Background(), plainCode); err != nil {
		t.Fatalf("InsertCode: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"plain-pkce-code"},
		"redirect_uri":  {"https://client.example.com/callback"},
		"code_verifier": {"some-challenge"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleToken(deps.store, oidcMgr, deps.issuer, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported PKCE method, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var errResp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("expected error=invalid_grant, got %q", errResp["error"])
	}
}

// TestHandleToken_StrictUpstreamRefreshFailure verifies that when
// BOUNCER_STRICT_UPSTREAM_REFRESH=true and the upstream refresh call fails,
// the token endpoint returns invalid_grant.
func TestHandleToken_StrictUpstreamRefreshFailure(t *testing.T) {
	t.Setenv("BOUNCER_STRICT_UPSTREAM_REFRESH", "true")

	deps := newTestDeps(t)

	// Fake upstream that always returns 500 on /token (to force refresh failure).
	var srvURL string
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srvURL,
				"authorization_endpoint": srvURL + "/auth",
				"token_endpoint":         srvURL + "/token",
				"userinfo_endpoint":      srvURL + "/userinfo",
				"jwks_uri":               srvURL + "/jwks",
			})
		case "/token":
			http.Error(w, "server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = failSrv.URL
	t.Cleanup(failSrv.Close)
	deps.rc.ProviderIssuer = failSrv.URL

	oidcMgr := oidc.NewManager()
	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	// Encrypt a fake upstream refresh token so handleRefreshToken tries to rotate it.
	encUpstream, err := deps.cipher.Encrypt([]byte("upstream-refresh-token-value"))
	if err != nil {
		t.Fatalf("cipher.Encrypt: %v", err)
	}

	rawRT, hashRT, expiry, err := deps.issuer.MintRefreshToken()
	if err != nil {
		t.Fatalf("MintRefreshToken: %v", err)
	}
	rt := store.RefreshToken{
		TokenHash:          hashRT,
		Sub:                "testuser",
		Resource:           deps.rc.Name,
		ClientID:           "test-client-id",
		ClaimsJSON:         `{}`,
		Scopes:             "openid",
		UpstreamRefreshEnc: encUpstream,
		ExpiresAt:          expiry,
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

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for strict upstream refresh failure, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var errResp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("expected error=invalid_grant, got %q", errResp["error"])
	}
}
