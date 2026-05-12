package as_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
)

func TestHandleProtectedResource(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()
	as.HandleProtectedResource(deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["resource"] != deps.rc.PublicBase {
		t.Errorf("resource = %q, want %q", body["resource"], deps.rc.PublicBase)
	}

	as_arr, ok := body["authorization_servers"].([]any)
	if !ok || len(as_arr) == 0 {
		t.Errorf("authorization_servers missing or empty")
	}
	if as_arr[0] != deps.rc.PublicBase {
		t.Errorf("authorization_servers[0] = %q, want %q", as_arr[0], deps.rc.PublicBase)
	}

	bearerMethods, ok := body["bearer_methods_supported"].([]any)
	if !ok || len(bearerMethods) == 0 || bearerMethods[0] != "header" {
		t.Errorf("bearer_methods_supported should be [header], got %v", body["bearer_methods_supported"])
	}
}

func TestHandleAuthorizationServer(t *testing.T) {
	deps := newTestDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	as.HandleAuthorizationServer(deps.rc, rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	checks := map[string]string{
		"issuer":                 deps.rc.PublicBase,
		"authorization_endpoint": deps.rc.PublicBase + "/oauth/authorize",
		"token_endpoint":         deps.rc.PublicBase + "/oauth/token",
		"registration_endpoint":  deps.rc.PublicBase + "/oauth/register",
		"jwks_uri":               deps.rc.PublicBase + "/oauth/jwks.json",
	}
	for field, expected := range checks {
		if body[field] != expected {
			t.Errorf("%s = %q, want %q", field, body[field], expected)
		}
	}
}
