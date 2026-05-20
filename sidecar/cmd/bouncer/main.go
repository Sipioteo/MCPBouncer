package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Sipioteo/MCPBouncer/sidecar/internal/as"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/audit"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/config"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/crypto"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/httpx"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/keys"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/logx"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/metrics"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/oidc"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/store"
	"github.com/Sipioteo/MCPBouncer/sidecar/internal/tokens"
)

func main() {
	// Configure logger. BOUNCER_LOG_LEVEL accepts trace|debug|info|warn|error.
	// See internal/logx for the level semantics.
	logLevel := logx.ParseLevel(os.Getenv("BOUNCER_LOG_LEVEL"))
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:       logLevel,
		ReplaceAttr: logx.ReplaceLevel,
	}))
	slog.SetDefault(logger)
	slog.Info("logger configured", "level", logLevel.String())

	// Read env vars.
	dbPath := envOr("BOUNCER_DB_PATH", "/data/bouncer.db")
	listenAddr := envOr("BOUNCER_LISTEN_ADDR", ":8080")
	encKey := mustEnv("BOUNCER_ENCRYPTION_KEY")

	rotationDays := envDuration("BOUNCER_KEY_ROTATION_DAYS", 30, 24*time.Hour)
	overlapHours := envDuration("BOUNCER_KEY_OVERLAP_HOURS", 24, time.Hour)
	accessTTL := envDuration("BOUNCER_ACCESS_TOKEN_TTL", 1, time.Hour)
	refreshTTL := envDuration("BOUNCER_REFRESH_TOKEN_TTL", 30, 24*time.Hour)
	clientTTL := envDuration("BOUNCER_CLIENT_TTL_DAYS", 90, 24*time.Hour)
	registerLimit := envInt("BOUNCER_REGISTER_RATE_LIMIT", 10)
	registerWindow := envDuration("BOUNCER_REGISTER_RATE_WINDOW", 1, time.Hour)
	metricsAddr := envOr("BOUNCER_METRICS_ADDR", ":9090")

	// Open store.
	db, err := store.Open(dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	s := store.NewStore(db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init cipher with key versioning. On first boot the env key is seeded
	// into encryption_keys as the active key (id "k1"); subsequent boots
	// load all rows and treat the env value as the legacy-decryption
	// fallback only. See internal/crypto for the wire format.
	cipher, err := crypto.NewCipherWithStore(ctx, s, encKey)
	if err != nil {
		slog.Error("failed to init cipher", "error", err)
		os.Exit(1)
	}
	slog.Info("cipher ready", "active_key_id", cipher.ActiveKeyID())

	// Init key rotator.
	rotator := keys.New(s, rotationDays, overlapHours, accessTTL)

	if err := rotator.Ensure(ctx); err != nil {
		slog.Error("failed to ensure signing key", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := rotator.Run(ctx); err != nil && err != context.Canceled {
			slog.Error("rotator error", "error", err)
		}
	}()

	// Init OIDC manager and token issuer.
	oidcMgr := oidc.NewManager()
	issuer := tokens.NewIssuer(rotator, accessTTL, refreshTTL)

	// Periodic DB cleanup: expired auth_sessions, codes, refresh_tokens,
	// signing_keys, plus stale clients past clientTTL. See internal/store/janitor.go.
	go store.Run(ctx, s, time.Minute, clientTTL)

	// Rate limiter for /oauth/register. Default: 10 req/h per IP.
	registerLimiter := httpx.NewLimiter(ctx, registerLimit, registerWindow)
	defer registerLimiter.Close()

	// Async audit logger backed by SQLite. Records OAuth events (DCR, authorize,
	// token issuance/refresh, revoke, introspect, userinfo) via a path-keyed
	// middleware. Drops events on backpressure rather than blocking handlers.
	auditLog := audit.NewSQLiteLogger(s)
	defer auditLog.Close()

	// Prometheus metrics server on a separate listener so it isn't exposed
	// behind Traefik. Default :9090. Set BOUNCER_METRICS_ADDR="" to disable.
	if metricsAddr != "" {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", metrics.Handler())
		metricsSrv := &http.Server{
			Addr:         metricsAddr,
			Handler:      mmux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			slog.Info("metrics listening", "addr", metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server error", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
	}

	// Build mux.
	mux := http.NewServeMux()

	// JWKS endpoint — no X-MCPB-* headers required.
	mux.HandleFunc("/oauth/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		as.HandleJWKS(rotator, w, r)
	})

	// Middleware that requires full X-MCPB-* headers, persists config, then dispatches.
	withRC := func(handler func(*config.ResourceConfig, http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rc, err := config.FromRequest(r)
			if err != nil {
				http.Error(w, "missing X-MCPB-* headers: "+err.Error(), http.StatusBadRequest)
				return
			}
			// Persist (cheap upsert) for audit trail and JWKS fallback.
			if persistErr := rc.PersistEncrypted(r.Context(), s, cipher); persistErr != nil {
				slog.Warn("failed to persist resource config", "resource", rc.Name, "error", persistErr)
			}
			handler(rc, w, r)
		}
	}

	mux.HandleFunc("/.well-known/oauth-protected-resource", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleProtectedResource(rc, w, r)
	}))
	mux.HandleFunc("/.well-known/oauth-authorization-server", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleAuthorizationServer(rc, w, r)
	}))
	mux.HandleFunc("/.well-known/openid-configuration", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleOpenIDConfiguration(rc, w, r)
	}))

	registerHandler := withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleRegister(s, rc, w, r)
	})
	mux.Handle("/oauth/register", registerLimiter.Middleware(registerHandler))

	mux.HandleFunc("/oauth/authorize", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleAuthorize(s, oidcMgr, rc, w, r)
	}))

	mux.HandleFunc("/oauth/callback", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleCallback(s, oidcMgr, cipher, rc, w, r)
	}))

	mux.HandleFunc("/oauth/token", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleToken(s, oidcMgr, issuer, cipher, rc, w, r)
	}))

	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		as.HandleRevoke(s, w, r)
	})

	mux.HandleFunc("/oauth/introspect", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleIntrospect(s, rotator, rc, w, r)
	}))

	mux.HandleFunc("/oauth/userinfo", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleUserinfo(s, rotator, rc, w, r)
	}))

	// Health check (not proxied by plugin, useful for internal monitoring).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      logRequests(auditOAuth(auditLog, mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		slog.Info("bouncer listening", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// auditEventTypeByPath maps OAuth path -> audit event type. Anything not in
// this map is not audited (well-known docs, JWKS, healthz, metrics).
var auditEventTypeByPath = map[string]string{
	"/oauth/register":   "dcr.register",
	"/oauth/authorize":  "oauth.authorize",
	"/oauth/callback":   "oauth.callback",
	"/oauth/token":      "oauth.token",
	"/oauth/revoke":     "oauth.revoke",
	"/oauth/introspect": "oauth.introspect",
	"/oauth/userinfo":   "oauth.userinfo",
}

func auditOAuth(logger audit.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evt, audited := auditEventTypeByPath[r.URL.Path]
		if !audited {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		logger.Record(r.Context(), audit.Event{
			Type:      evt,
			IP:        audit.ClientIP(r),
			Success:   sw.status < 400,
			Details:   map[string]any{"method": r.Method, "status": sw.status},
			Timestamp: time.Now(),
		})
	})
}

// logRequests wraps the mux with INFO-level request logging.
// Logs: method, path, status, duration, plus the X-MCPB-Resource header that
// the plugin injects so we know which MCP the request was for.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"resource", r.Header.Get("X-MCPB-Resource"),
			"remote", r.RemoteAddr,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

// envDuration reads a duration env var. Accepts either:
//   - Go duration syntax: "1h", "30m", "720h"
//   - plain integer multiplied by `unit`: "30" with unit=24h → 30 days
func envDuration(key string, defaultVal int, unit time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(defaultVal) * unit
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return time.Duration(defaultVal) * unit
	}
	return time.Duration(n) * unit
}
