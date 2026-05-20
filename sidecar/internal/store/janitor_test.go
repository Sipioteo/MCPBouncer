package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// openJanitorDB opens a dedicated test DB for janitor tests.
func openJanitorDB(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "janitor_test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewStore(db)
}

// TestJanitorDeletesExpiredRefreshTokens verifies that one tick of the janitor
// removes expired refresh tokens and leaves fresh ones intact.
func TestJanitorDeletesExpiredRefreshTokens(t *testing.T) {
	s := openJanitorDB(t)
	ctx := context.Background()

	expired := store.RefreshToken{
		TokenHash: "expired-hash",
		Sub:       "user1",
		Resource:  "wiki",
		ClientID:  "cid1",
		Scopes:    "openid",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
	}
	fresh := store.RefreshToken{
		TokenHash: "fresh-hash",
		Sub:       "user2",
		Resource:  "wiki",
		ClientID:  "cid2",
		Scopes:    "openid",
		ExpiresAt: time.Now().Add(24 * time.Hour), // not yet expired
	}

	if err := s.InsertRefreshToken(ctx, expired); err != nil {
		t.Fatalf("InsertRefreshToken expired: %v", err)
	}
	if err := s.InsertRefreshToken(ctx, fresh); err != nil {
		t.Fatalf("InsertRefreshToken fresh: %v", err)
	}

	// Run janitor with a very short interval so one tick fires quickly.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Run(runCtx, s, 10*time.Millisecond, 30*24*time.Hour)
	}()

	// Wait enough for at least one tick.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// Expired token must be gone.
	got, err := s.GetRefreshTokenByHash(ctx, "expired-hash")
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash expired: %v", err)
	}
	if got != nil {
		t.Fatal("expected expired refresh token to be deleted")
	}

	// Fresh token must still exist.
	got2, err := s.GetRefreshTokenByHash(ctx, "fresh-hash")
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash fresh: %v", err)
	}
	if got2 == nil {
		t.Fatal("expected fresh refresh token to still exist")
	}
}

// TestJanitorDeletesStaleClients verifies that stale clients are removed and
// fresh clients are preserved.
func TestJanitorDeletesStaleClients(t *testing.T) {
	s := openJanitorDB(t)
	ctx := context.Background()

	staleTime := time.Now().Add(-100 * 24 * time.Hour) // 100 days ago
	freshTime := time.Now()

	stale := store.Client{
		ClientID:                    "stale-cid",
		ClientSecretHash:            "hash-stale",
		RedirectURIsJSON:            `["https://stale.example.com/cb"]`,
		RegistrationAccessTokenHash: "rat-stale",
		Resource:                    "wiki",
		Scopes:                      "openid",
		CreatedAt:                   staleTime,
		LastUsedAt:                  staleTime,
	}
	fresh := store.Client{
		ClientID:                    "fresh-cid",
		ClientSecretHash:            "hash-fresh",
		RedirectURIsJSON:            `["https://fresh.example.com/cb"]`,
		RegistrationAccessTokenHash: "rat-fresh",
		Resource:                    "wiki",
		Scopes:                      "openid",
		CreatedAt:                   freshTime,
		LastUsedAt:                  freshTime,
	}

	if err := s.InsertClient(ctx, stale); err != nil {
		t.Fatalf("InsertClient stale: %v", err)
	}
	if err := s.InsertClient(ctx, fresh); err != nil {
		t.Fatalf("InsertClient fresh: %v", err)
	}

	clientTTL := 30 * 24 * time.Hour

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Run(runCtx, s, 10*time.Millisecond, clientTTL)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// Stale client must be gone.
	got, err := s.GetClient(ctx, "stale-cid")
	if err != nil {
		t.Fatalf("GetClient stale: %v", err)
	}
	if got != nil {
		t.Fatal("expected stale client to be deleted")
	}

	// Fresh client must still exist.
	got2, err := s.GetClient(ctx, "fresh-cid")
	if err != nil {
		t.Fatalf("GetClient fresh: %v", err)
	}
	if got2 == nil {
		t.Fatal("expected fresh client to still exist")
	}
}

// TestJanitorExitsOnCancel verifies that the janitor goroutine stops cleanly
// when the context is cancelled (no goroutine leak).
func TestJanitorExitsOnCancel(t *testing.T) {
	s := openJanitorDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Run(ctx, s, 1*time.Hour, 30*24*time.Hour)
	}()

	cancel()

	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("janitor goroutine did not exit after context cancellation")
	}
}
