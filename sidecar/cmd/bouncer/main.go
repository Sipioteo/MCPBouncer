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

	"github.com/sipiote/mcpbouncer-sidecar/internal/as"
	"github.com/sipiote/mcpbouncer-sidecar/internal/config"
	"github.com/sipiote/mcpbouncer-sidecar/internal/crypto"
	"github.com/sipiote/mcpbouncer-sidecar/internal/keys"
	"github.com/sipiote/mcpbouncer-sidecar/internal/oidc"
	"github.com/sipiote/mcpbouncer-sidecar/internal/store"
	"github.com/sipiote/mcpbouncer-sidecar/internal/tokens"
)

func main() {
	// Configure logger.
	logLevel := slog.LevelInfo
	if os.Getenv("BOUNCER_LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Read env vars.
	dbPath := envOr("BOUNCER_DB_PATH", "/data/bouncer.db")
	listenAddr := envOr("BOUNCER_LISTEN_ADDR", ":8080")
	encKey := mustEnv("BOUNCER_ENCRYPTION_KEY")

	rotationDays := envDuration("BOUNCER_KEY_ROTATION_DAYS", 30, 24*time.Hour)
	overlapHours := envDuration("BOUNCER_KEY_OVERLAP_HOURS", 24, time.Hour)
	accessTTL := envDuration("BOUNCER_ACCESS_TOKEN_TTL", 1, time.Hour)
	refreshTTL := envDuration("BOUNCER_REFRESH_TOKEN_TTL", 30, 24*time.Hour)

	// Open store.
	db, err := store.Open(dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	s := store.NewStore(db)

	// Init cipher.
	cipher, err := crypto.NewCipher(encKey)
	if err != nil {
		slog.Error("failed to init cipher", "error", err)
		os.Exit(1)
	}

	// Init key rotator.
	rotator := keys.New(s, rotationDays, overlapHours, accessTTL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Cleanup goroutine.
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				cleanCtx := context.Background()
				if err := s.DeleteExpiredAuthSessions(cleanCtx); err != nil {
					slog.Warn("cleanup auth_sessions error", "error", err)
				}
				if err := s.DeleteExpiredCodes(cleanCtx); err != nil {
					slog.Warn("cleanup codes error", "error", err)
				}
				if err := s.DeleteExpiredRefreshTokens(cleanCtx); err != nil {
					slog.Warn("cleanup refresh_tokens error", "error", err)
				}
				if err := s.DeleteExpiredSigningKeys(cleanCtx); err != nil {
					slog.Warn("cleanup signing_keys error", "error", err)
				}
			}
		}
	}()

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

	mux.HandleFunc("/oauth/register", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleRegister(s, rc, w, r)
	}))

	mux.HandleFunc("/oauth/authorize", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleAuthorize(s, oidcMgr, rc, w, r)
	}))

	mux.HandleFunc("/oauth/callback", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleCallback(s, oidcMgr, cipher, rc, w, r)
	}))

	mux.HandleFunc("/oauth/token", withRC(func(rc *config.ResourceConfig, w http.ResponseWriter, r *http.Request) {
		as.HandleToken(s, oidcMgr, issuer, cipher, rc, w, r)
	}))

	// Health check (not proxied by plugin, useful for internal monitoring).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

// envDuration reads an integer env var and multiplies by unit.
func envDuration(key string, defaultVal int, unit time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(defaultVal) * unit
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return time.Duration(defaultVal) * unit
	}
	return time.Duration(n) * unit
}
