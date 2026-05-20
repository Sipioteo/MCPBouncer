package as_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
)

// mintExpiredToken builds and signs a JWT with exp in the past using the
// rotator's active key, allowing us to test the expiry check path.
func mintExpiredToken(t *testing.T, deps *testDeps) string {
	t.Helper()
	activeKey, priv, err := deps.rotator.ActiveKey(context.Background())
	if err != nil {
		t.Fatalf("ActiveKey: %v", err)
	}
	hdrJSON, _ := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"typ": "at+jwt",
		"kid": activeKey.Kid,
	})
	payJSON, _ := json.Marshal(map[string]any{
		"sub": "expired-user",
		"iss": deps.rc.PublicBase,
		"aud": []string{deps.rc.PublicBase + "/"},
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"nbf": time.Now().Add(-2 * time.Hour).Unix(),
	})
	h := base64.RawURLEncoding.EncodeToString(hdrJSON)
	p := base64.RawURLEncoding.EncodeToString(payJSON)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestHandleUserinfo_HappyPath(t *testing.T) {
	deps := newTestDeps(t)

	extraClaims := map[string]any{
		"email":      "alice@example.com",
		"name":       "Alice",
		"given_name": "Alice",
	}
	tok, _, err := deps.issuer.MintAccessToken(context.Background(), deps.rc, "alice", "openid email profile", "test-client", extraClaims)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var profile map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&profile); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if profile["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", profile["sub"])
	}
	if profile["email"] != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", profile["email"])
	}
	if profile["name"] != "Alice" {
		t.Errorf("name = %v, want Alice", profile["name"])
	}
	// JWT-specific claims must not appear.
	for _, forbidden := range []string{"exp", "iat", "iss", "aud", "jti", "nbf", "client_id"} {
		if _, ok := profile[forbidden]; ok {
			t.Errorf("profile should not contain claim %q", forbidden)
		}
	}
}

func TestHandleUserinfo_PostMethod(t *testing.T) {
	deps := newTestDeps(t)

	tok, _, err := deps.issuer.MintAccessToken(context.Background(), deps.rc, "bob", "openid", "test-client", nil)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUserinfo_ExpiredToken(t *testing.T) {
	deps := newTestDeps(t)
	expiredTok := mintExpiredToken(t, deps)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+expiredTok)
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUserinfo_MalformedToken(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt.at.all")
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed token, got %d", rr.Code)
	}
}

func TestHandleUserinfo_NoAuthorizationHeader(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing header, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestHandleUserinfo_WrongScheme(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for Basic scheme, got %d", rr.Code)
	}
}

func TestHandleUserinfo_WrongMethod(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodPut, "/oauth/userinfo", nil)
	rr := httptest.NewRecorder()
	as.HandleUserinfo(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", rr.Code)
	}
}
