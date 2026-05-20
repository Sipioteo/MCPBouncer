package as_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
)

func TestHandleRegister(t *testing.T) {
	deps := newTestDeps(t)

	body := `{"redirect_uris":["https://client.example.com/callback"],"client_name":"Test Client","scope":"openid email"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	as.HandleRegister(deps.store, deps.rc, rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	clientID, ok := resp["client_id"].(string)
	if !ok || clientID == "" {
		t.Errorf("expected non-empty client_id")
	}
	if resp["client_secret"] == "" {
		t.Errorf("expected non-empty client_secret")
	}
	if resp["client_secret_expires_at"] != float64(0) {
		t.Errorf("client_secret_expires_at should be 0")
	}
	if resp["registration_access_token"] == "" {
		t.Errorf("expected registration_access_token")
	}

	// Verify persisted.
	stored, err := deps.store.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if stored == nil {
		t.Fatalf("client not found in store after registration")
	}
	if stored.Resource != deps.rc.Name {
		t.Errorf("client resource = %q, want %q", stored.Resource, deps.rc.Name)
	}
}

func TestHandleRegister_NoRedirectURIs(t *testing.T) {
	deps := newTestDeps(t)

	body := `{"redirect_uris":[]}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	as.HandleRegister(deps.store, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleRegister_InvalidRedirectURI(t *testing.T) {
	deps := newTestDeps(t)

	body := `{"redirect_uris":["not-a-valid-url"]}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	as.HandleRegister(deps.store, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleRegister_BlockedSchemes(t *testing.T) {
	blocked := []string{
		"javascript:alert(1)",
		"data:text/html,<h1>hi</h1>",
		"file:///etc/passwd",
		"vbscript:msgbox(1)",
		"blob:https://example.com/something",
		"about:blank",
	}
	for _, uri := range blocked {
		t.Run(uri, func(t *testing.T) {
			deps := newTestDeps(t)
			body := `{"redirect_uris":["` + uri + `"]}`
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			rr := httptest.NewRecorder()
			as.HandleRegister(deps.store, deps.rc, rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("uri %q: expected 400, got %d; body: %s", uri, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleRegister_HTTPLoopback(t *testing.T) {
	tests := []struct {
		uri    string
		wantOK bool
	}{
		{"http://localhost/callback", true},
		{"http://127.0.0.1/callback", true},
		{"http://evil.com/callback", false},
		{"http://192.168.1.1/callback", false},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			deps := newTestDeps(t)
			body := `{"redirect_uris":["` + tc.uri + `"]}`
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			rr := httptest.NewRecorder()
			as.HandleRegister(deps.store, deps.rc, rr, req)
			if tc.wantOK && rr.Code != http.StatusCreated {
				t.Errorf("uri %q: expected 201, got %d; body: %s", tc.uri, rr.Code, rr.Body.String())
			}
			if !tc.wantOK && rr.Code != http.StatusBadRequest {
				t.Errorf("uri %q: expected 400, got %d; body: %s", tc.uri, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleRegister_ValidSchemes(t *testing.T) {
	valid := []string{
		"https://client.example.com/callback",
		"mcp://client.example.com/callback",
	}
	for _, uri := range valid {
		t.Run(uri, func(t *testing.T) {
			deps := newTestDeps(t)
			body := `{"redirect_uris":["` + uri + `"]}`
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			rr := httptest.NewRecorder()
			as.HandleRegister(deps.store, deps.rc, rr, req)
			if rr.Code != http.StatusCreated {
				t.Errorf("uri %q: expected 201, got %d; body: %s", uri, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleRegister_InitialAccessToken(t *testing.T) {
	const token = "super-secret-initial-token"

	t.Run("no auth header → 401", func(t *testing.T) {
		t.Setenv("BOUNCER_DCR_INITIAL_TOKEN", token)
		deps := newTestDeps(t)
		body := `{"redirect_uris":["https://client.example.com/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		rr := httptest.NewRecorder()
		as.HandleRegister(deps.store, deps.rc, rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d; body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong token → 401", func(t *testing.T) {
		t.Setenv("BOUNCER_DCR_INITIAL_TOKEN", token)
		deps := newTestDeps(t)
		body := `{"redirect_uris":["https://client.example.com/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()
		as.HandleRegister(deps.store, deps.rc, rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d; body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("correct token → 201", func(t *testing.T) {
		t.Setenv("BOUNCER_DCR_INITIAL_TOKEN", token)
		deps := newTestDeps(t)
		body := `{"redirect_uris":["https://client.example.com/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		as.HandleRegister(deps.store, deps.rc, rr, req)
		if rr.Code != http.StatusCreated {
			t.Errorf("expected 201, got %d; body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("env unset → open registration", func(t *testing.T) {
		t.Setenv("BOUNCER_DCR_INITIAL_TOKEN", "")
		deps := newTestDeps(t)
		body := `{"redirect_uris":["https://client.example.com/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		rr := httptest.NewRecorder()
		as.HandleRegister(deps.store, deps.rc, rr, req)
		if rr.Code != http.StatusCreated {
			t.Errorf("expected 201 (open), got %d; body: %s", rr.Code, rr.Body.String())
		}
	})
}
