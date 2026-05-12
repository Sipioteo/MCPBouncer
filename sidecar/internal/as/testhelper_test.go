package as_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sipiote/mcpbouncer-sidecar/internal/config"
	"github.com/sipiote/mcpbouncer-sidecar/internal/crypto"
	"github.com/sipiote/mcpbouncer-sidecar/internal/keys"
	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
	"github.com/sipiote/mcpbouncer-sidecar/internal/tokens"
)

// testKeyB64 is a 32-byte zero-key in base64 for testing only.
var testKeyB64 = base64.StdEncoding.EncodeToString(make([]byte, 32))

type testDeps struct {
	store   *store.Store
	cipher  *crypto.Cipher
	rotator *keys.Rotator
	issuer  *tokens.Issuer
	rc      *config.ResourceConfig
}

func newTestDeps(t *testing.T) *testDeps {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	s := store.NewStore(db)

	cipher, err := crypto.NewCipher(testKeyB64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	rotator := keys.New(s, 30*24*time.Hour, 24*time.Hour, time.Hour)
	if err := rotator.Ensure(context.Background()); err != nil {
		t.Fatalf("rotator.Ensure: %v", err)
	}

	issuer := tokens.NewIssuer(rotator, time.Hour, 30*24*time.Hour)

	rc := &config.ResourceConfig{
		Name:           "wiki",
		PublicBase:     "https://mcp.example.com/wiki",
		ProviderIssuer: "https://idp.example.com",
		ClientID:       "upstream-client-id",
		ClientSecret:   "upstream-client-secret",
		Scopes:         "openid email profile",
		Audience:       "wiki",
	}

	return &testDeps{
		store:   s,
		cipher:  cipher,
		rotator: rotator,
		issuer:  issuer,
		rc:      rc,
	}
}

// fakeUpstreamServer creates a fake upstream IdP. The returned server URL is
// the issuer; callers should set deps.rc.ProviderIssuer = srv.URL.
func fakeUpstreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			_ = r.ParseForm()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "upstream_at",
				"refresh_token": "upstream_rt",
				"id_token":      fakeMiniJWT("testuser"),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":   "testuser",
				"email": "test@example.com",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// fakeMiniJWT makes a minimal unsigned JWT (for tests only).
func fakeMiniJWT(sub string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `","iss":"test","email":"` + sub + `@example.com"}`))
	return hdr + "." + pay + ".sig"
}

// insertTestClient inserts a client row and returns the client_id.
func insertTestClient(t *testing.T, s *store.Store, redirectURIs []string, resource string) string {
	t.Helper()
	urisJSON, _ := json.Marshal(redirectURIs)
	c := store.Client{
		ClientID:                    "test-client-id",
		ClientSecretHash:            hexSHA256("test-secret"),
		RedirectURIsJSON:            string(urisJSON),
		RegistrationAccessTokenHash: hexSHA256("test-rat"),
		Resource:                    resource,
		Scopes:                      "openid email profile",
		CreatedAt:                   time.Now(),
	}
	if err := s.InsertClient(context.Background(), c); err != nil {
		t.Fatalf("InsertClient: %v", err)
	}
	return c.ClientID
}

func hexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// s256 computes PKCE S256 challenge from verifier.
func s256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
