package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// okHandler returns 200 OK for every request.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// newReq builds a GET request with the given X-Forwarded-For value.
func newReq(xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestBelowLimit_AllPass(t *testing.T) {
	l := NewLimiter(context.Background(), 5, time.Hour)
	defer l.Close()
	h := l.Middleware(okHandler)

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq("10.0.0.1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}
}

func TestAtLimit_Returns429(t *testing.T) {
	l := NewLimiter(context.Background(), 3, time.Hour)
	defer l.Close()
	h := l.Middleware(okHandler)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq("10.0.0.2"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}

	// 4th request must be rejected.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq("10.0.0.2"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
}

func TestRetryAfterHeader_PresentOn429(t *testing.T) {
	l := NewLimiter(context.Background(), 1, time.Hour)
	defer l.Close()
	h := l.Middleware(okHandler)

	ip := "10.0.0.3"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(ip)) // consumes the one token

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(ip))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}

	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("Retry-After header missing on 429")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After not an integer: %q", ra)
	}
	if secs < 1 {
		t.Fatalf("Retry-After must be >= 1, got %d", secs)
	}
}

func TestWindowExpiry_AllowsRequestsAgain(t *testing.T) {
	window := 100 * time.Millisecond
	l := NewLimiter(context.Background(), 2, window)
	defer l.Close()
	h := l.Middleware(okHandler)

	ip := "10.0.0.4"

	// Exhaust the limit.
	for i := 0; i < 2; i++ {
		h.ServeHTTP(httptest.NewRecorder(), newReq(ip))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(ip))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 before window expires, got %d", rec.Code)
	}

	// Wait for the window to roll over.
	time.Sleep(window + 10*time.Millisecond)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(ip))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after window expires, got %d", rec.Code)
	}
}

func TestDifferentIPs_IndependentBuckets(t *testing.T) {
	l := NewLimiter(context.Background(), 1, time.Hour)
	defer l.Close()
	h := l.Middleware(okHandler)

	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	for _, ip := range ips {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq(ip))
		if rec.Code != http.StatusOK {
			t.Fatalf("IP %s first request: got %d, want 200", ip, rec.Code)
		}
	}

	// Each IP should now be at its limit — second request must be 429.
	for _, ip := range ips {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq(ip))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("IP %s second request: got %d, want 429", ip, rec.Code)
		}
	}
}

func TestXForwardedFor_FirstValueUsed(t *testing.T) {
	l := NewLimiter(context.Background(), 1, time.Hour)
	defer l.Close()
	h := l.Middleware(okHandler)

	// Two XFF values — only the first (1.2.3.4) should be used as the key.
	// 5.6.7.8 should be treated as a different client.
	xff1 := "1.2.3.4, 5.6.7.8"
	xff2 := "1.2.3.4, 9.9.9.9" // same first IP, different proxy chain

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(xff1))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rec.Code)
	}

	// Same first IP -> should be rate-limited together.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(xff2))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request with same first XFF: got %d, want 429", rec.Code)
	}
}
