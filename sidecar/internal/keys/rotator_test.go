package keys_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sipiote/mcpbouncer-sidecar/internal/keys"
	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewStore(db)
}

func TestEnsureCreatesActiveKey(t *testing.T) {
	s := openTestStore(t)
	r := keys.New(s, 30*24*time.Hour, 24*time.Hour, time.Hour)
	ctx := context.Background()

	if err := r.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	k, priv, err := r.ActiveKey(ctx)
	if err != nil {
		t.Fatalf("ActiveKey: %v", err)
	}
	if k == nil {
		t.Fatal("expected active key")
	}
	if k.Status != "active" {
		t.Fatalf("expected status active, got %s", k.Status)
	}
	if len(priv) == 0 {
		t.Fatal("expected non-empty private key")
	}
}

func TestEnsureIdempotent(t *testing.T) {
	s := openTestStore(t)
	r := keys.New(s, 30*24*time.Hour, 24*time.Hour, time.Hour)
	ctx := context.Background()

	if err := r.Ensure(ctx); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if err := r.Ensure(ctx); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	all, err := r.AllPublishableKeys(ctx)
	if err != nil {
		t.Fatalf("AllPublishableKeys: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 key after two Ensures, got %d", len(all))
	}
}

func TestAllPublishableKeysJWKS(t *testing.T) {
	s := openTestStore(t)
	r := keys.New(s, 30*24*time.Hour, 24*time.Hour, time.Hour)
	ctx := context.Background()

	if err := r.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	all, err := r.AllPublishableKeys(ctx)
	if err != nil {
		t.Fatalf("AllPublishableKeys: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected at least one publishable key")
	}

	jwks, err := keys.PublishableJWKS(all)
	if err != nil {
		t.Fatalf("PublishableJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" {
		t.Fatalf("unexpected JWK fields: %+v", jwk)
	}
	if jwk.X == "" {
		t.Fatal("JWK X must not be empty")
	}
}
