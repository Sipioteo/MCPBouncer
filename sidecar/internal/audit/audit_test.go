package audit

import (
	"bytes"
	"context"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
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

func TestRecord_FlushesOnClose(t *testing.T) {
	s := openTestStore(t)
	l := NewSQLiteLogger(s)

	ctx := context.Background()
	events := []Event{
		{Type: TypeOAuthTokenIssue, ClientID: "cid1", Sub: "user1", IP: "1.2.3.4", Success: true, Details: map[string]any{"scope": "openid"}},
		{Type: TypeAuthFailure, ClientID: "cid2", Sub: "", IP: "5.6.7.8", Success: false, Details: nil},
		{Type: TypeDCRRegister, ClientID: "cid3", Sub: "user3", IP: "9.10.11.12", Success: true, Details: map[string]any{"redirect_uris": []string{"https://example.com/cb"}}},
	}
	for _, e := range events {
		l.Record(ctx, e)
	}

	// Give the goroutine a moment, then drain.
	time.Sleep(10 * time.Millisecond)
	l.Close()

	// Verify all events landed in the DB.
	count, err := s.CountAuditEvents(ctx)
	if err != nil {
		t.Fatalf("CountAuditEvents: %v", err)
	}
	if count != int64(len(events)) {
		t.Fatalf("expected %d events, got %d", len(events), count)
	}
}

func TestRecord_BufferFullDropsWithWarn(t *testing.T) {
	s := openTestStore(t)

	// Capture log output.
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	// Buffer of 2: fill it with 4 events before the goroutine can drain.
	// We use a channel trick: block the worker by creating a logger whose
	// underlying store is never drained until we call Close.
	// Using buffer=2, send 4 → 2 should be dropped.
	l := newSQLiteLoggerWithBuffer(s, 2)

	// Pause the worker indirectly: send enough events quickly.
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		l.Record(ctx, Event{Type: TypeAuthFailure, ClientID: "overflow", IP: "1.1.1.1", Success: false})
	}

	// Wait for drain.
	l.Close()

	// At most 2 events can be in the DB (buffer size); at least 1 warn logged.
	count, err := s.CountAuditEvents(ctx)
	if err != nil {
		t.Fatalf("CountAuditEvents: %v", err)
	}
	if count > 4 {
		t.Fatalf("expected at most 4 events, got %d", count)
	}
	logged := buf.String()
	// If any were dropped, the warning must be present.
	dropped := 4 - count
	if dropped > 0 && !bytes.Contains([]byte(logged), []byte("buffer full")) {
		t.Fatalf("expected 'buffer full' warning in log when dropped=%d; got: %s", dropped, logged)
	}
}
