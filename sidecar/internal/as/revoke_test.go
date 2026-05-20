package as_test

import (
	"context"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// insertRTForClient mints and inserts a refresh token owned by clientID.
// It returns the raw (un-hashed) token value.
func insertRTForClient(t *testing.T, deps *testDeps, clientID string) string {
	t.Helper()
	raw, hash, expiry, err := deps.issuer.MintRefreshToken()
	if err != nil {
		t.Fatalf("MintRefreshToken: %v", err)
	}
	rt := store.RefreshToken{
		TokenHash: hash,
		Sub:       "testuser",
		Resource:  deps.rc.Name,
		ClientID:  clientID,
		Scopes:    "openid email",
		ExpiresAt: expiry,
	}
	if err := deps.store.InsertRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}
	return raw
}

func doRevoke(t *testing.T, deps *testDeps, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	as.HandleRevoke(deps.store, rr, req)
	return rr
}

// TestHandleRevoke_HappyPath: insert a refresh token, revoke it, confirm gone.
func TestHandleRevoke_HappyPath(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	rawRT := insertRTForClient(t, deps, "test-client-id")

	form := url.Values{
		"token":           {rawRT},
		"client_id":       {"test-client-id"},
		"client_secret":   {"test-secret"},
		"token_type_hint": {"refresh_token"},
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Token must be gone.
	hash := tokens.HashToken(rawRT)
	stored, err := deps.store.GetRefreshTokenByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if stored != nil {
		t.Fatal("expected refresh token to be deleted, but it still exists")
	}
}

// TestHandleRevoke_WrongClient: RT belongs to clientA; clientB tries to revoke -> 200 but RT intact.
func TestHandleRevoke_WrongClient(t *testing.T) {
	deps := newTestDeps(t)

	// Insert two clients.
	insertTestClientWithSecret(t, deps.store, "client-a", hexSHA256("secret-a"), []string{"https://a.example.com/cb"}, deps.rc.Name)
	insertTestClientWithSecret(t, deps.store, "client-b", hexSHA256("secret-b"), []string{"https://b.example.com/cb"}, deps.rc.Name)

	rawRT := insertRTForClient(t, deps, "client-a")

	form := url.Values{
		"token":         {rawRT},
		"client_id":     {"client-b"},
		"client_secret": {"secret-b"},
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Token must still exist.
	hash := tokens.HashToken(rawRT)
	stored, err := deps.store.GetRefreshTokenByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if stored == nil {
		t.Fatal("expected refresh token to still exist, but it was deleted")
	}
}

// TestHandleRevoke_MissingClientSecret: confidential client without secret -> 401.
func TestHandleRevoke_MissingClientSecret(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	form := url.Values{
		"token":     {"sometoken"},
		"client_id": {"test-client-id"},
		// client_secret intentionally omitted
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleRevoke_GetMethod: non-POST -> 405.
func TestHandleRevoke_GetMethod(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/revoke", nil)
	rr := httptest.NewRecorder()
	as.HandleRevoke(deps.store, rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// TestHandleRevoke_AccessTokenHint: hint=access_token always returns 200.
func TestHandleRevoke_AccessTokenHint(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	form := url.Values{
		"token":           {"some.jwt.token"},
		"client_id":       {"test-client-id"},
		"client_secret":   {"test-secret"},
		"token_type_hint": {"access_token"},
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleRevoke_NoHint: absent hint treated as refresh_token.
func TestHandleRevoke_NoHint(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	rawRT := insertRTForClient(t, deps, "test-client-id")

	form := url.Values{
		"token":         {rawRT},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
		// no token_type_hint
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	hash := tokens.HashToken(rawRT)
	stored, err := deps.store.GetRefreshTokenByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if stored != nil {
		t.Fatal("expected refresh token to be deleted, but it still exists")
	}
}

// TestHandleRevoke_UnknownToken: revoke a token that doesn't exist -> 200.
func TestHandleRevoke_UnknownToken(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	form := url.Values{
		"token":         {"nonexistent-token-value"},
		"client_id":     {"test-client-id"},
		"client_secret": {"test-secret"},
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleRevoke_InvalidClientSecret: wrong secret -> 401.
func TestHandleRevoke_InvalidClientSecret(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	form := url.Values{
		"token":         {"sometoken"},
		"client_id":     {"test-client-id"},
		"client_secret": {"wrong-secret"},
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleRevoke_UnknownClientHint: unrecognised hint treated as refresh_token.
func TestHandleRevoke_UnknownHint(t *testing.T) {
	deps := newTestDeps(t)
	insertTestClient(t, deps.store, []string{"https://client.example.com/cb"}, deps.rc.Name)

	rawRT := insertRTForClient(t, deps, "test-client-id")

	form := url.Values{
		"token":           {rawRT},
		"client_id":       {"test-client-id"},
		"client_secret":   {"test-secret"},
		"token_type_hint": {"id_token"}, // unrecognised
	}
	rr := doRevoke(t, deps, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Token should be deleted (treated as refresh_token).
	hash := tokens.HashToken(rawRT)
	stored, err := deps.store.GetRefreshTokenByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if stored != nil {
		t.Fatal("expected refresh token to be deleted, but it still exists")
	}
}
