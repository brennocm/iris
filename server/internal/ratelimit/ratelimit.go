// Package ratelimit limits requests per client with a token bucket.
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limiter gives each client a bucket of Burst tokens refilled at Rate per second.
type Limiter struct {
	rate  float64
	burst float64
	max   int
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing perMinute requests per client on average, in bursts of up to
// burst. At most maxClients buckets are kept; when full, idle buckets are dropped first and,
// if none is idle, new clients share one overflow bucket so memory stays bounded.
func New(perMinute, burst, maxClients int) *Limiter {
	return &Limiter{
		rate: float64(perMinute) / 60, burst: float64(burst), max: maxClients,
		now: time.Now, buckets: map[string]*bucket{},
	}
}

const overflowKey = "\x00overflow"

// Allow takes one token from key's bucket and reports whether there was one.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			l.sweep(now)
		}
		if len(l.buckets) >= l.max {
			key = overflowKey
			b = l.buckets[key]
		}
		if b == nil {
			b = &bucket{tokens: l.burst, last: now}
			l.buckets[key] = b
		}
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled completely: forgetting them changes nothing.
func (l *Limiter) sweep(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if k != overflowKey && now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}

// ClientIP returns the address to rate limit. With header empty it is the TCP peer. Behind a
// proxy, header names the one the proxy sets (for example "X-Forwarded-For" or
// "Fly-Client-IP"); only configure it when every request goes through that proxy, or clients
// can pick their own key. For X-Forwarded-For the last entry is used, the one the proxy added.
func ClientIP(r *http.Request, header string) string {
	if header != "" {
		if v := r.Header.Get(header); v != "" {
			parts := strings.Split(v, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware rejects requests over the limit with 429 and a Retry-After header.
func (l *Limiter) Middleware(header string, next http.Handler) http.Handler {
	// Seconds until one token comes back (Retry-After takes whole seconds).
	retry := strconv.Itoa(int(math.Ceil(1 / l.rate)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(ClientIP(r, header)) {
			w.Header().Set("Retry-After", retry)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
