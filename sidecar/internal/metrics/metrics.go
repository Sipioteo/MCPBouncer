// Package metrics exposes Prometheus metrics for MCPBouncer sidecar.
// Metrics are registered in a private registry and served via Handler().
// The metrics server itself (addr/start) is wired by the caller.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reg = prometheus.NewRegistry()

	tokenIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bouncer_token_issued_total",
			Help: "Total number of tokens issued, by grant_type.",
		},
		[]string{"grant_type"},
	)

	tokenRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bouncer_token_refresh_total",
			Help: `Total token refresh attempts. result is "ok", "upstream_failed", or "invalid".`,
		},
		[]string{"result"},
	)

	dcrRegisterTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bouncer_dcr_register_total",
			Help: `Total DCR registration attempts. result is "ok" or an error category.`,
		},
		[]string{"result"},
	)

	authFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bouncer_auth_failures_total",
			Help: "Total authentication failures by reason.",
		},
		[]string{"reason"},
	)

	tokenEndpointDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "bouncer_token_endpoint_duration_seconds",
			Help:    "Latency of the token endpoint in seconds.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
	)

	refreshTokensInDB = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "bouncer_refresh_tokens_in_db",
		Help: "Current number of refresh tokens stored in the database.",
	})

	clientsInDB = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "bouncer_clients_in_db",
		Help: "Current number of registered clients stored in the database.",
	})

	signingKeysActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "bouncer_signing_keys_active",
		Help: "Current number of active signing keys.",
	})
)

func init() {
	reg.MustRegister(
		tokenIssuedTotal,
		tokenRefreshTotal,
		dcrRegisterTotal,
		authFailuresTotal,
		tokenEndpointDuration,
		refreshTokensInDB,
		clientsInDB,
		signingKeysActive,
	)
}

// Handler returns an http.Handler that serves Prometheus metrics from the
// private registry. Mount this on the internal metrics port.
func Handler() http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// TokenIssued increments bouncer_token_issued_total for the given grant type
// (e.g. "authorization_code", "refresh_token", "client_credentials").
func TokenIssued(grantType string) {
	tokenIssuedTotal.WithLabelValues(grantType).Inc()
}

// TokenRefresh increments bouncer_token_refresh_total.
// result must be one of "ok", "upstream_failed", or "invalid".
func TokenRefresh(result string) {
	tokenRefreshTotal.WithLabelValues(result).Inc()
}

// DCRRegister increments bouncer_dcr_register_total.
// result must be one of "ok" or an error category string.
func DCRRegister(result string) {
	dcrRegisterTotal.WithLabelValues(result).Inc()
}

// AuthFailure increments bouncer_auth_failures_total.
// reason must be one of: "invalid_client", "invalid_grant", "invalid_redirect_uri",
// "rate_limited", "missing_secret", "upstream_unreachable".
func AuthFailure(reason string) {
	authFailuresTotal.WithLabelValues(reason).Inc()
}

// ObserveTokenDuration records a token endpoint request duration.
func ObserveTokenDuration(d time.Duration) {
	tokenEndpointDuration.Observe(d.Seconds())
}

// TokenEndpointTimer returns a prometheus.Timer that, when ObserveDuration is
// called, records elapsed time into bouncer_token_endpoint_duration_seconds.
//
// Usage:
//
//	t := metrics.TokenEndpointTimer()
//	defer t.ObserveDuration()
func TokenEndpointTimer() *prometheus.Timer {
	return prometheus.NewTimer(tokenEndpointDuration)
}

// UpdateDBGauges sets the three database-size gauges atomically.
// Call this from a periodic goroutine (e.g. every 30 s).
func UpdateDBGauges(refreshN, clientN, keyN int64) {
	refreshTokensInDB.Set(float64(refreshN))
	clientsInDB.Set(float64(clientN))
	signingKeysActive.Set(float64(keyN))
}
