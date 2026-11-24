package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBucketRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60, 3, 10) // one per second, bursts of three
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d of the burst rejected", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("fourth request in the same instant allowed")
	}
	if !l.Allow("b") {
		t.Fatal("another client was limited by the first one")
	}
	now = now.Add(time.Second)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("expected exactly one token after one second")
	}
}

func TestMemoryStaysBounded(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60, 2, 2)
	l.now = func() time.Time { return now }
	l.Allow("a")
	l.Allow("b")
	// Table full and nobody idle: new clients share the overflow bucket.
	if !l.Allow("c") || !l.Allow("d") || l.Allow("e") {
		t.Fatal("overflow bucket should allow its burst, then limit")
	}
	if len(l.buckets) != 3 {
		t.Fatalf("expected 2 clients + overflow, got %d", len(l.buckets))
	}
	// Once a and b have refilled they can be forgotten and new clients get their own bucket.
	now = now.Add(10 * time.Second)
	if !l.Allow("f") {
		t.Fatal("new client after sweep rejected")
	}
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("idle bucket was not swept")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 1.2.3.4")
	if got := ClientIP(r, ""); got != "10.0.0.1" {
		t.Fatalf("no header configured: %s", got)
	}
	if got := ClientIP(r, "X-Forwarded-For"); got != "1.2.3.4" {
		t.Fatalf("forwarded: %s (must be the proxy-added entry, not the client-supplied one)", got)
	}
}

func TestMiddleware(t *testing.T) {
	l := New(1, 1, 10)
	h := l.Middleware("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = "1.1.1.1:1"
		h.ServeHTTP(w, r)
		return w
	}
	if do().Code != 204 {
		t.Fatal("first request limited")
	}
	w := do()
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("got %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
}
