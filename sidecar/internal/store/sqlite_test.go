package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

func openTestDB(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewStore(db)
}

func TestSigningKey(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	retiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	err := s.InsertSigningKey(ctx, "kid1", "EdDSA", []byte("priv"), []byte("pub"), retiresAt, "active")
	if err != nil {
		t.Fatalf("InsertSigningKey: %v", err)
	}
	k, err := s.GetActiveSigningKey(ctx)
	if err != nil {
		t.Fatalf("GetActiveSigningKey: %v", err)
	}
	if k == nil {
		t.Fatal("expected active key, got nil")
	}
	if k.Kid != "kid1" || k.Alg != "EdDSA" || string(k.PrivatePEM) != "priv" {
		t.Fatalf("unexpected key: %+v", k)
	}

	keys, err := s.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestClient(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	c := store.Client{
		ClientID:                    "cid1",
		ClientSecretHash:            "hash1",
		RedirectURIsJSON:            `["https://example.com/cb"]`,
		RegistrationAccessTokenHash: "rat1",
		Resource:                    "wiki",
		Scopes:                      "openid email",
		CreatedAt:                   time.Now().Truncate(time.Second),
	}
	if err := s.InsertClient(ctx, c); err != nil {
		t.Fatalf("InsertClient: %v", err)
	}
	got, err := s.GetClient(ctx, "cid1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got == nil || got.ClientID != "cid1" || got.Resource != "wiki" {
		t.Fatalf("unexpected client: %+v", got)
	}
}

func TestAuthSession(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	sess := store.AuthSession{
		State:                "st1",
		CodeChallenge:        "cc1",
		CodeChallengeMethod:  "S256",
		RedirectURI:          "https://client.example.com/cb",
		ClientID:             "cid1",
		Resource:             "wiki",
		Scopes:               "openid",
		ProviderIssuer:       "https://accounts.google.com",
		PublicBase:           "https://mcp.example.com/wiki",
		UpstreamState:        "ust1",
		UpstreamPKCEVerifier: "verifier1",
		OriginalState:        "origst1",
		CreatedAt:            time.Now().Truncate(time.Second),
		ExpiresAt:            time.Now().Add(10 * time.Minute).Truncate(time.Second),
	}
	if err := s.InsertAuthSession(ctx, sess); err != nil {
		t.Fatalf("InsertAuthSession: %v", err)
	}
	got, err := s.GetAuthSession(ctx, "st1")
	if err != nil {
		t.Fatalf("GetAuthSession: %v", err)
	}
	if got == nil || got.State != "st1" || got.Resource != "wiki" {
		t.Fatalf("unexpected session: %+v", got)
	}
	if err := s.DeleteAuthSession(ctx, "st1"); err != nil {
		t.Fatalf("DeleteAuthSession: %v", err)
	}
	got2, _ := s.GetAuthSession(ctx, "st1")
	if got2 != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestCode(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	c := store.Code{
		Code:                "code1",
		ClientID:            "cid1",
		Resource:            "wiki",
		Sub:                 "user1",
		ClaimsJSON:          `{"email":"u@example.com"}`,
		UpstreamRefreshEnc:  []byte("encrypted"),
		Scopes:              "openid",
		RedirectURI:         "https://client.example.com/cb",
		CodeChallenge:       "cc1",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute).Truncate(time.Second),
	}
	if err := s.InsertCode(ctx, c); err != nil {
		t.Fatalf("InsertCode: %v", err)
	}
	got, err := s.GetCode(ctx, "code1")
	if err != nil {
		t.Fatalf("GetCode: %v", err)
	}
	if got == nil || got.Sub != "user1" {
		t.Fatalf("unexpected code: %+v", got)
	}
	if err := s.DeleteCode(ctx, "code1"); err != nil {
		t.Fatalf("DeleteCode: %v", err)
	}
}

func TestRefreshToken(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	rt := store.RefreshToken{
		TokenHash:          "hash1",
		Sub:                "user1",
		Resource:           "wiki",
		ClientID:           "cid1",
		UpstreamRefreshEnc: []byte("enc"),
		Scopes:             "openid",
		ExpiresAt:          time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second),
	}
	if err := s.InsertRefreshToken(ctx, rt); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}
	got, err := s.GetRefreshTokenByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if got == nil || got.Sub != "user1" {
		t.Fatalf("unexpected rt: %+v", got)
	}
	if err := s.DeleteRefreshTokenByHash(ctx, "hash1"); err != nil {
		t.Fatalf("DeleteRefreshTokenByHash: %v", err)
	}
}

func TestResourceConfig(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	rc := store.ResourceConfig{
		Name:            "wiki",
		ProviderIssuer:  "https://accounts.google.com",
		ClientID:        "gcid",
		ClientSecretEnc: []byte("encrypted_secret"),
		Scopes:          "openid email",
		Audience:        "wiki",
		UpdatedAt:       time.Now().Truncate(time.Second),
	}
	if err := s.UpsertResourceConfig(ctx, rc); err != nil {
		t.Fatalf("UpsertResourceConfig: %v", err)
	}
	got, err := s.GetResourceConfig(ctx, "wiki")
	if err != nil {
		t.Fatalf("GetResourceConfig: %v", err)
	}
	if got == nil || got.ClientID != "gcid" {
		t.Fatalf("unexpected config: %+v", got)
	}

	// Upsert again to verify update.
	rc.ClientID = "gcid2"
	if err := s.UpsertResourceConfig(ctx, rc); err != nil {
		t.Fatalf("UpsertResourceConfig update: %v", err)
	}
	got2, _ := s.GetResourceConfig(ctx, "wiki")
	if got2.ClientID != "gcid2" {
		t.Fatalf("expected updated clientID, got %s", got2.ClientID)
	}
}
