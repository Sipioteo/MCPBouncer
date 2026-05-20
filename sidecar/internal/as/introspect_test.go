package as_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

// doIntrospect sends a POST to the introspection endpoint with the given form values.
func doIntrospect(t *testing.T, deps *testDeps, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleIntrospect(deps.store, deps.rotator, deps.rc, rr, req)
	return rr
}

// decodeIntrospectResp decodes a JSON introspection response body.
func decodeIntrospectResp(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return resp
}

// mintAT mints a real signed access token for clientID/sub using the test deps.
func mintAT(t *testing.T, deps *testDeps, clientID, sub string) string {
	t.Helper()
	tok, _, err := deps.issuer.MintAccessToken(context.Background(), deps.rc, sub, "openid email", clientID, nil)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	return tok
}

// --- Tests ---

// TestHandleIntrospect_HappyPathAccessToken: issue an AT, introspect as same client -> active=true.
func TestHandleIntrospect_HappyPathAccessToken(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "test-client-id", hexSHA256("test-secret"), []string{"https://client.example.com/cb"}, deps.rc.Name)

	at := mintAT(t, deps, "test-client-id", "testuser")

	rr := doIntrospect(t, deps, url.Values{
		"token":         {at},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeIntrospectResp(t, rr)
	if active, _ := resp["active"].(bool); !active {
		t.Fatalf("expected active=true, got: %v", resp)
	}
	if sub, _ := resp["sub"].(string); sub != "testuser" {
		t.Errorf("want sub=testuser, got %q", sub)
	}
	if cid, _ := resp["client_id"].(string); cid != "test-client-id" {
		t.Errorf("want client_id=test-client-id, got %q", cid)
	}
	if scope, _ := resp["scope"].(string); scope == "" {
		t.Errorf("expected scope to be present")
	}
	if _, ok := resp["exp"]; !ok {
		t.Errorf("expected exp to be present")
	}
	if _, ok := resp["iat"]; !ok {
		t.Errorf("expected iat to be present")
	}
}

// TestHandleIntrospect_AccessTokenWrongClient: AT introspected by a different client -> active=false.
func TestHandleIntrospect_AccessTokenWrongClient(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "client-a", hexSHA256("secret-a"), []string{"https://a.example.com/cb"}, deps.rc.Name)
	insertTestClientWithSecret(t, deps.store, "client-b", hexSHA256("secret-b"), []string{"https://b.example.com/cb"}, deps.rc.Name)

	at := mintAT(t, deps, "client-a", "testuser")

	rr := doIntrospect(t, deps, url.Values{
		"token":         {at},
		"client_id":     {"client-b"},
		"client_secret": {"secret-b"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeIntrospectResp(t, rr)
	if active, _ := resp["active"].(bool); active {
		t.Fatalf("expected active=false for cross-client introspection")
	}
}

// TestHandleIntrospect_ExpiredAccessToken: expired AT -> active=false.
func TestHandleIntrospect_ExpiredAccessToken(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "test-client-id", hexSHA256("test-secret"), []string{"https://client.example.com/cb"}, deps.rc.Name)

	// Create an issuer with a 0-second TTL so the token is immediately expired.
	expiredIssuer := tokens.NewIssuer(deps.rotator, -1*time.Second, 30*24*time.Hour)
	at, _, err := expiredIssuer.MintAccessToken(context.Background(), deps.rc, "testuser", "openid", "test-client-id", nil)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	rr := doIntrospect(t, deps, url.Values{
		"token":         {at},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeIntrospectResp(t, rr)
	if active, _ := resp["active"].(bool); active {
		t.Fatalf("expected active=false for expired token")
	}
}

// TestHandleIntrospect_HappyPathRefreshToken: insert a RT, introspect it -> active=true.
func TestHandleIntrospect_HappyPathRefreshToken(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "test-client-id", hexSHA256("test-secret"), []string{"https://client.example.com/cb"}, deps.rc.Name)

	raw, hash, expiry, err := deps.issuer.MintRefreshToken()
	if err != nil {
		t.Fatalf("MintRefreshToken: %v", err)
	}
	rt := store.RefreshToken{
		TokenHash: hash,
		Sub:       "rtuser",
		Resource:  deps.rc.Name,
		ClientID:  "test-client-id",
		Scopes:    "openid email",
		ExpiresAt: expiry,
	}
	if err := deps.store.InsertRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}

	rr := doIntrospect(t, deps, url.Values{
		"token":           {raw},
		"token_type_hint": {"refresh_token"},
		"client_id":       {"test-client-id"},
		"client_secret":   {"test-secret"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeIntrospectResp(t, rr)
	if active, _ := resp["active"].(bool); !active {
		t.Fatalf("expected active=true for refresh token, got: %v", resp)
	}
	if sub, _ := resp["sub"].(string); sub != "rtuser" {
		t.Errorf("want sub=rtuser, got %q", sub)
	}
	if cid, _ := resp["client_id"].(string); cid != "test-client-id" {
		t.Errorf("want client_id=test-client-id, got %q", cid)
	}
}

// TestHandleIntrospect_GarbageToken: garbage string -> active=false.
func TestHandleIntrospect_GarbageToken(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "test-client-id", hexSHA256("test-secret"), []string{"https://client.example.com/cb"}, deps.rc.Name)

	rr := doIntrospect(t, deps, url.Values{
		"token":         {"this.is.garbage"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeIntrospectResp(t, rr)
	if active, _ := resp["active"].(bool); active {
		t.Fatalf("expected active=false for garbage token")
	}
}

// TestHandleIntrospect_GetMethod: GET -> 405.
func TestHandleIntrospect_GetMethod(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/introspect", nil)
	rr := httptest.NewRecorder()
	as.HandleIntrospect(deps.store, deps.rotator, deps.rc, rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// TestHandleIntrospect_MissingClientSecret: confidential client without secret -> 401.
func TestHandleIntrospect_MissingClientSecret(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClientWithSecret(t, deps.store, "test-client-id", hexSHA256("test-secret"), []string{"https://client.example.com/cb"}, deps.rc.Name)

	at := mintAT(t, deps, "test-client-id", "testuser")

	rr := doIntrospect(t, deps, url.Values{
		"token":     {at},
		"client_id": {"test-client-id"},
		// client_secret intentionally omitted
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
}
