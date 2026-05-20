// Package httpx provides HTTP middleware utilities for the MCPBouncer sidecar.
//
// The rate limiter in this file is intended to be wired at /oauth/register
// (via cmd/bouncer/main.go) to guard the Dynamic Client Registration endpoint
// against bulk registrations. Traefik is expected to sit in front of the
// sidecar and sets the real client IP in the X-Forwarded-For header; this
// middleware reads the first value from that header before falling back to
// r.RemoteAddr.
//
// Default suggested parameters: limit=10, window=time.Hour.
package httpx

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucket holds the token-bucket state for a single client IP.
type bucket struct {
	// tokens is the number of remaining requests allowed in the current window.
	tokens int
	// windowStart is when the current window opened.
	windowStart time.Time
	// lastSeen is the last time this bucket was touched (used for GC).
	lastSeen time.Time
}

// Limiter is a per-IP token-bucket rate limiter. Create one with
// NewLimiter, wire its Middleware method into your handler chain, and
// call Close when the server shuts down to stop the background GC goroutine.
type Limiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket

	cancel context.CancelFunc
	done   chan struct{}
}

// NewLimiter creates a Limiter that allows limit requests per window per IP.
// A background goroutine wakes every window interval and evicts buckets that
// have not been touched for more than 2*window. The goroutine is stopped when
// ctx is cancelled or when Close is called.
func NewLimiter(ctx context.Context, limit int, window time.Duration) *Limiter {
	ctx, cancel := context.WithCancel(ctx)
	l := &Limiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go l.gc(ctx)
	return l
}

// RateLimit is a convenience wrapper that creates a Limiter and immediately
// returns an http.Handler. The underlying Limiter's GC goroutine runs until
// ctx is cancelled. Use NewLimiter + Middleware if you need to call Close.
func RateLimit(ctx context.Context, next http.Handler, limit int, window time.Duration) http.Handler {
	return NewLimiter(ctx, limit, window).Middleware(next)
}

// Close stops the background GC goroutine and waits for it to exit.
func (l *Limiter) Close() {
	l.cancel()
	<-l.done
}

// Middleware returns an http.Handler that enforces the rate limit.
// Requests that exceed the limit receive a 429 Too Many Requests response
// with a Retry-After header indicating how many seconds remain in the current
// window (rounded up to the nearest second).
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		now := time.Now()

		l.mu.Lock()
		b, ok := l.buckets[ip]
		if !ok || now.Sub(b.windowStart) >= l.window {
			// Start a fresh window.
			b = &bucket{
				tokens:      l.limit,
				windowStart: now,
				lastSeen:    now,
			}
			l.buckets[ip] = b
		}

		if b.tokens <= 0 {
			// Compute seconds remaining in the window, rounded up.
			remaining := b.windowStart.Add(l.window).Sub(now)
			retryAfter := int(math.Ceil(remaining.Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			l.mu.Unlock()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		b.tokens--
		b.lastSeen = now
		l.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client IP address from the request.
// It prefers the first value in X-Forwarded-For (set by Traefik with the real
// client IP) and falls back to the host portion of r.RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF may be a comma-separated list; take the first entry.
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			xff = xff[:idx]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// gc periodically removes stale buckets to bound memory growth.
// A bucket is considered stale if it has not been touched for more than
// 2*window, meaning it will get a fresh window on the next request anyway.
func (l *Limiter) gc(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cutoff := now.Add(-2 * l.window)
			l.mu.Lock()
			for ip, b := range l.buckets {
				if b.lastSeen.Before(cutoff) {
					delete(l.buckets, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}
