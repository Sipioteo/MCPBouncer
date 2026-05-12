package as_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sipiote/mcpbouncer-sidecar/internal/as"
	"github.com/sipiote/mcpbouncer-sidecar/internal/oidc"
	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
)

func TestHandleCallback_FullRoundTrip(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL

	oidcMgr := oidc.NewManager()

	// Insert an auth session using upstream_state as PK.
	upstreamState := base64.RawURLEncoding.EncodeToString([]byte("upstream-state-value-16b"))
	sess := store.AuthSession{
		State:                upstreamState,
		CodeChallenge:        s256("client-verifier"),
		CodeChallengeMethod:  "S256",
		RedirectURI:          "https://client.example.com/callback",
		ClientID:             "client-abc",
		Resource:             deps.rc.Name,
		Scopes:               "openid email",
		ProviderIssuer:       upstream.URL,
		PublicBase:           deps.rc.PublicBase,
		UpstreamState:        upstreamState,
		UpstreamPKCEVerifier: "upstream-verifier",
		OriginalState:        "original-state-xyz",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(10 * time.Minute),
	}
	if err := deps.store.InsertAuthSession(context.Background(), sess); err != nil {
		t.Fatalf("InsertAuthSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=upstream_code&state="+url.QueryEscape(upstreamState), nil)
	rr := httptest.NewRecorder()
	as.HandleCallback(deps.store, oidcMgr, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d; body: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}

	parsedLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	localCode := parsedLoc.Query().Get("code")
	if localCode == "" {
		t.Fatal("expected code in redirect Location")
	}
	if parsedLoc.Query().Get("state") != "original-state-xyz" {
		t.Errorf("state = %q, want original-state-xyz", parsedLoc.Query().Get("state"))
	}

	codeRow, err := deps.store.GetCode(context.Background(), localCode)
	if err != nil {
		t.Fatalf("GetCode: %v", err)
	}
	if codeRow == nil {
		t.Fatal("code not found in store")
	}
	if codeRow.Sub != "testuser" {
		t.Errorf("sub = %q, want testuser", codeRow.Sub)
	}

	// Auth session should be deleted (single-use).
	sessDel, err := deps.store.GetAuthSession(context.Background(), upstreamState)
	if err != nil {
		t.Fatalf("GetAuthSession after delete: %v", err)
	}
	if sessDel != nil {
		t.Errorf("auth session should have been deleted after callback")
	}
}

func TestHandleCallback_UnknownState(t *testing.T) {
	deps := newTestDeps(t)
	upstream := fakeUpstreamServer(t)
	deps.rc.ProviderIssuer = upstream.URL
	oidcMgr := oidc.NewManager()

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=x&state=no-such-state", nil)
	rr := httptest.NewRecorder()
	as.HandleCallback(deps.store, oidcMgr, deps.cipher, deps.rc, rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
