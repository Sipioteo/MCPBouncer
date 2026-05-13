// Package logx adds a TRACE level to slog and a small helper for emitting
// trace records. INFO and above use the standard slog API.
//
// Levels (most verbose first):
//
//	trace — full JWT bodies, full HTTP request/response bodies, raw upstream payloads
//	debug — per-request OAuth params (no secrets), parse decisions, cache hits/misses
//	info  — HTTP access log, server start, key rotations, every minted token (summary)
//	warn  — recoverable conditions
//	error — failures
//
// Trace is intended for incident debugging; it can include sensitive material
// (tokens, refresh tokens, encrypted blobs decoded) and should never be the
// default level.
package logx

import (
	"context"
	"log/slog"
	"strings"
)

// LevelTrace is below slog.LevelDebug so a default-level INFO handler ignores it.
const LevelTrace = slog.Level(-8)

// ParseLevel maps a case-insensitive env-var value to a slog.Level.
// Recognised: "trace", "debug", "info", "warn"/"warning", "error".
// Unknown values fall back to slog.LevelInfo.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ReplaceLevel produces a slog ReplaceAttr that prints "TRACE" instead of the
// numeric -8 when the level is LevelTrace. Use it in slog.HandlerOptions.
func ReplaceLevel(groups []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == LevelTrace {
		a.Value = slog.StringValue("TRACE")
	}
	return a
}

// Trace logs at the TRACE level. Cheap when the handler filters it out
// because slog elides the attribute construction.
func Trace(msg string, args ...any) {
	slog.Default().Log(context.Background(), LevelTrace, msg, args...)
}

// TraceCtx is the context-aware variant.
func TraceCtx(ctx context.Context, msg string, args ...any) {
	slog.Default().Log(ctx, LevelTrace, msg, args...)
}
