package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scrape calls the metrics handler and returns the full body as a string.
func scrape(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handler returned %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// assertContains fails the test if substr is not found in body.
func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("expected metric output to contain %q\n\nFull output:\n%s", substr, body)
	}
}

func TestTokenIssuedCounter(t *testing.T) {
	// Reset state by using a fresh call; counters are cumulative so we read
	// baseline then increment and assert the label appears.
	TokenIssued("authorization_code")
	TokenIssued("authorization_code")
	TokenIssued("refresh_token")

	body := scrape(t)
	assertContains(t, body, `bouncer_token_issued_total{grant_type="authorization_code"}`)
	assertContains(t, body, `bouncer_token_issued_total{grant_type="refresh_token"}`)
}

func TestTokenRefreshCounter(t *testing.T) {
	TokenRefresh("ok")
	TokenRefresh("upstream_failed")
	TokenRefresh("invalid")

	body := scrape(t)
	assertContains(t, body, `bouncer_token_refresh_total{result="ok"}`)
	assertContains(t, body, `bouncer_token_refresh_total{result="upstream_failed"}`)
	assertContains(t, body, `bouncer_token_refresh_total{result="invalid"}`)
}

func TestDCRRegisterCounter(t *testing.T) {
	DCRRegister("ok")
	DCRRegister("bad_request")

	body := scrape(t)
	assertContains(t, body, `bouncer_dcr_register_total{result="ok"}`)
	assertContains(t, body, `bouncer_dcr_register_total{result="bad_request"}`)
}

func TestAuthFailureCounter(t *testing.T) {
	AuthFailure("invalid_client")
	AuthFailure("rate_limited")
	AuthFailure("missing_secret")

	body := scrape(t)
	assertContains(t, body, `bouncer_auth_failures_total{reason="invalid_client"}`)
	assertContains(t, body, `bouncer_auth_failures_total{reason="rate_limited"}`)
	assertContains(t, body, `bouncer_auth_failures_total{reason="missing_secret"}`)
}

func TestUpdateDBGauges(t *testing.T) {
	UpdateDBGauges(42, 7, 3)

	body := scrape(t)
	assertContains(t, body, "bouncer_refresh_tokens_in_db 42")
	assertContains(t, body, "bouncer_clients_in_db 7")
	assertContains(t, body, "bouncer_signing_keys_active 3")
}

func TestUpdateDBGaugesOverwrite(t *testing.T) {
	UpdateDBGauges(100, 50, 10)
	UpdateDBGauges(1, 2, 3)

	body := scrape(t)
	assertContains(t, body, "bouncer_refresh_tokens_in_db 1")
	assertContains(t, body, "bouncer_clients_in_db 2")
	assertContains(t, body, "bouncer_signing_keys_active 3")
}

func TestTokenEndpointTimer(t *testing.T) {
	timer := TokenEndpointTimer()
	timer.ObserveDuration()

	body := scrape(t)
	assertContains(t, body, "bouncer_token_endpoint_duration_seconds_count")
	assertContains(t, body, "bouncer_token_endpoint_duration_seconds_bucket")
}

func TestObserveTokenDuration(t *testing.T) {
	ObserveTokenDuration(0)

	body := scrape(t)
	assertContains(t, body, "bouncer_token_endpoint_duration_seconds_sum")
}
