package store

import (
	"context"
	"log/slog"
	"time"
)

// Run starts the periodic DB cleanup loop. On each interval tick it deletes:
//   - expired auth_sessions
//   - expired codes
//   - expired refresh_tokens
//   - expired signing_keys (status='retiring' past retires_at)
//   - clients whose last_used_at is older than clientTTL
//
// It returns when ctx is cancelled.
func Run(ctx context.Context, s *Store, interval time.Duration, clientTTL time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	tick := func() {
		// Use Background so a brief ctx cancel during shutdown doesn't abort
		// the in-flight DELETE statements mid-transaction.
		c := context.Background()
		if err := s.DeleteExpiredAuthSessions(c); err != nil {
			slog.Warn("janitor: DeleteExpiredAuthSessions", "err", err)
		}
		if err := s.DeleteExpiredCodes(c); err != nil {
			slog.Warn("janitor: DeleteExpiredCodes", "err", err)
		}
		if err := s.DeleteExpiredRefreshTokens(c); err != nil {
			slog.Warn("janitor: DeleteExpiredRefreshTokens", "err", err)
		}
		if err := s.DeleteExpiredSigningKeys(c); err != nil {
			slog.Warn("janitor: DeleteExpiredSigningKeys", "err", err)
		}
		if n, err := s.DeleteStaleClients(c, clientTTL); err != nil {
			slog.Warn("janitor: DeleteStaleClients", "err", err)
		} else if n > 0 {
			slog.Info("janitor: deleted stale clients", "count", n)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
