package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
)

func fakeIDToken(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `","iss":"test"}`))
	return header + "." + payload + ".fakesig"
}

func TestDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		issuer := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	defer srv.Close()

	mgr := oidc.NewManager()
	p, err := mgr.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if p.AuthEndpoint != srv.URL+"/auth" {
		t.Errorf("unexpected auth endpoint: %q", p.AuthEndpoint)
	}
	if p.TokenEndpoint != srv.URL+"/token" {
		t.Errorf("unexpected token endpoint: %q", p.TokenEndpoint)
	}

	// Second call uses cache.
	p2, err := mgr.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover (cached): %v", err)
	}
	if p2.Issuer != p.Issuer {
		t.Errorf("cached issuer mismatch")
	}
}

func TestDiscoverIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": "https://wrong.issuer.example.com",
		})
	}))
	defer srv.Close()

	mgr := oidc.NewManager()
	_, err := mgr.Discover(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for issuer mismatch, got nil")
	}
}

func TestExchangeCode(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":        srvURL,
				"token_endpoint": srvURL + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", 400)
				return
			}
			if r.FormValue("grant_type") != "authorization_code" {
				http.Error(w, "wrong grant_type", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "upstream_access",
				"refresh_token": "upstream_refresh",
				"id_token":      fakeIDToken("user123"),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	mgr := oidc.NewManager()
	p, err := mgr.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	tr, err := mgr.ExchangeCode(context.Background(), p, "cid", "csec", "code123", "http://localhost/callback", "verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tr.AccessToken != "upstream_access" {
		t.Errorf("unexpected access_token: %q", tr.AccessToken)
	}
	if tr.RefreshToken != "upstream_refresh" {
		t.Errorf("unexpected refresh_token: %q", tr.RefreshToken)
	}
}

func TestDecodeIDToken(t *testing.T) {
	raw := fakeIDToken("alice")
	claims, err := oidc.DecodeIDToken(raw)
	if err != nil {
		t.Fatalf("DecodeIDToken: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", claims["sub"])
	}
}
