package as_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
)

func TestHandleAuthorize_RedirectsToUpstream(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	oidcMgr := oidc.NewManager()

	// Build PKCE.
	verifier := base64.RawURLEncoding.EncodeToString([]byte("test-verifier-padded-to-32-bytes!"))
	challenge := s256(verifier)

	reqURL := "/oauth/authorize?response_type=code&client_id=test-client-id" +
		"&redirect_uri=https://client.example.com/callback" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256&state=mystate"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	as.HandleAuthorize(deps.store, oidcMgr, deps.rc, rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("expected code_challenge in upstream redirect")
	}
	if q.Get("state") == "" {
		t.Errorf("expected state in upstream redirect")
	}
	// upstream redirect_uri should be our callback.
	if q.Get("redirect_uri") != deps.rc.PublicBase+"/oauth/callback" {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), deps.rc.PublicBase+"/oauth/callback")
	}
}

func TestHandleAuthorize_UnknownClient(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	challenge := s256("someverifier")
	reqURL := "/oauth/authorize?response_type=code&client_id=no-such-client" +
		"&redirect_uri=https://client.example.com/callback" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	as.HandleAuthorize(deps.store, oidcMgr, deps.rc, rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleAuthorize_PromptNoneForwardedToUpstream(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL

	insertTestClient(t, deps.store, []string{"https://client.example.com/callback"}, deps.rc.Name)

	oidcMgr := oidc.NewManager()

	verifier := base64.RawURLEncoding.EncodeToString([]byte("test-verifier-padded-to-32-bytes!"))
	challenge := s256(verifier)

	reqURL := "/oauth/authorize?response_type=code&client_id=test-client-id" +
		"&redirect_uri=https://client.example.com/callback" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256&state=mystate&prompt=none"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	as.HandleAuthorize(deps.store, oidcMgr, deps.rc, rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if parsed.Query().Get("prompt") != "none" {
		t.Errorf("expected prompt=none in upstream redirect, got %q", parsed.Query().Get("prompt"))
	}
}

func TestHandleAuthorize_WrongRedirectURI(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	insertTestClient(t, deps.store, []string{"https://allowed.example.com/cb"}, deps.rc.Name)

	challenge := s256("someverifier")
	reqURL := "/oauth/authorize?response_type=code&client_id=test-client-id" +
		"&redirect_uri=https://evil.example.com/cb" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	as.HandleAuthorize(deps.store, oidcMgr, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
