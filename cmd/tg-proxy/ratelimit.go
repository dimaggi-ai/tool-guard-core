package main

import (
	"sync"
	"time"
)

// tokenBucket implements a simple token-bucket rate limiter, one
// instance per identity. Refills lazily on read.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	cap        float64
	refillRate float64 // tokens per second
	last       time.Time
}

func newTokenBucket(rps, burst float64) *tokenBucket {
	return &tokenBucket{
		tokens:     burst,
		cap:        burst,
		refillRate: rps,
		last:       time.Now(),
	}
}

// take consumes one token if available; returns true on success,
// false when the bucket is empty (rate-limited).
func (b *tokenBucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.cap {
		b.tokens = b.cap
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// rateLimiter is the proxy-level keyed token-bucket store.
// Buckets are created on first request per key. To prevent unbounded
// growth when keying on session_id (which is per-conversation and can
// churn arbitrarily), the store evicts buckets whose `last` access
// is older than idleEvict, sweeping opportunistically on access.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	rps       float64
	burst     float64
	idleEvict time.Duration // buckets untouched for this long are dropped
	maxKeys   int           // hard cap; eviction fires once exceeded
}

// defaultIdleEvict is how long a per-key bucket stays alive without
// activity before being reaped.
const defaultIdleEvict = 30 * time.Minute

// defaultRateLimitMaxKeys caps the number of distinct rate-limit
// buckets in memory. At 100k entries × ~64 bytes each ≈ 6 MB.
const defaultRateLimitMaxKeys = 100_000

func newRateLimiter(rps, burst float64) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*tokenBucket),
		rps:       rps,
		burst:     burst,
		idleEvict: defaultIdleEvict,
		maxKeys:   defaultRateLimitMaxKeys,
	}
}

// sweepIdleLocked drops buckets whose last access is older than
// idleEvict. Caller must hold r.mu. O(n) over the bucket set; called
// only when the map crosses maxKeys.
func (r *rateLimiter) sweepIdleLocked() {
	cutoff := time.Now().Add(-r.idleEvict)
	for k, b := range r.buckets {
		b.mu.Lock()
		last := b.last
		b.mu.Unlock()
		if last.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

// allow returns true if a request keyed by `key` is permitted under
// the bucket. A bucket is created on first use; idle buckets are
// reaped opportunistically when the map crosses its cap.
//
// An empty key (the rate-limit-key-by field is missing or empty on
// the envelope — misconfigured client or hostile bypass attempt) is
// NOT exempted: all such requests share a single "_unknown" bucket
// so an attacker cannot dodge rate-limiting just by sending an
// envelope with no agent_id. Previously the empty-key path returned
// true unconditionally, which is a bypass class.
func (r *rateLimiter) allow(key string) bool {
	if r == nil {
		return true
	}
	if key == "" {
		key = "_unknown"
	}
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		if len(r.buckets) >= r.maxKeys {
			r.sweepIdleLocked()
		}
		b = newTokenBucket(r.rps, r.burst)
		r.buckets[key] = b
	}
	r.mu.Unlock()
	return b.take()
}

// stats returns the number of distinct keys observed. Exposed via
// /metrics.
func (r *rateLimiter) stats() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
