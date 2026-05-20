package audit

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
)

// Event types for structured audit logging.
const (
	TypeDCRRegister       = "dcr.register"
	TypeOAuthAuthorize    = "oauth.authorize"
	TypeOAuthTokenIssue   = "oauth.token.issue"
	TypeOAuthTokenRefresh = "oauth.token.refresh"
	TypeOAuthRevoke       = "oauth.revoke"
	TypeAuthFailure       = "auth.failure"
)

// Event represents a single audit event.
type Event struct {
	Type      string
	ClientID  string
	Sub       string
	IP        string
	Success   bool
	Details   map[string]any
	Timestamp time.Time
}

// Logger records audit events.
type Logger interface {
	Record(ctx context.Context, e Event)
	Close()
}

const defaultBufferSize = 1024

type sqliteLogger struct {
	s    *store.Store
	ch   chan Event
	done chan struct{}
}

// NewSQLiteLogger returns a Logger backed by the given Store.
// Events are written asynchronously via a buffered channel of size 1024.
func NewSQLiteLogger(s *store.Store) Logger {
	return newSQLiteLoggerWithBuffer(s, defaultBufferSize)
}

// newSQLiteLoggerWithBuffer is the package-internal constructor allowing a
// custom buffer size (used in tests).
func newSQLiteLoggerWithBuffer(s *store.Store, bufSize int) Logger {
	l := &sqliteLogger{
		s:    s,
		ch:   make(chan Event, bufSize),
		done: make(chan struct{}),
	}
	go l.run()
	return l
}

// Record enqueues an event for asynchronous persistence.
// If the buffer is full the event is dropped and a warning is logged.
func (l *sqliteLogger) Record(ctx context.Context, e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	select {
	case l.ch <- e:
	default:
		log.Printf("[audit] WARN: buffer full, dropping event type=%s client_id=%s", e.Type, e.ClientID)
	}
}

// Close drains pending events and waits for the worker goroutine to finish.
func (l *sqliteLogger) Close() {
	close(l.ch)
	<-l.done
}

func (l *sqliteLogger) run() {
	defer close(l.done)
	for e := range l.ch {
		l.persist(e)
	}
}

func (l *sqliteLogger) persist(e Event) {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		log.Printf("[audit] WARN: marshal details: %v", err)
		b = []byte("{}")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.s.InsertAuditEvent(ctx, e.Type, e.ClientID, e.Sub, e.IP, string(b), e.Success); err != nil {
		log.Printf("[audit] WARN: InsertAuditEvent: %v", err)
	}
}

// ClientIP extracts the client IP from a request.
// It prefers the first value of the X-Forwarded-For header,
// falling back to RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
