package main

import (
	"testing"
	"time"
)

func TestTokenBucket_AllowUpToBurstThenDeny(t *testing.T) {
	b := newTokenBucket(0.0001, 5) // ~no refill, burst of 5
	for i := 0; i < 5; i++ {
		if !b.take() {
			t.Fatalf("take #%d: expected allow", i)
		}
	}
	if b.take() {
		t.Fatalf("6th take: expected deny (burst exhausted)")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	b := newTokenBucket(10, 1) // 10 rps, burst 1
	if !b.take() {
		t.Fatalf("initial take: expected allow")
	}
	if b.take() {
		t.Fatalf("second take should be denied immediately")
	}
	time.Sleep(150 * time.Millisecond) // ~1.5 tokens accrued
	if !b.take() {
		t.Fatalf("after refill: expected allow")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	r := newRateLimiter(0.0001, 1)
	if !r.allow("alice") {
		t.Fatalf("alice 1st: deny")
	}
	if r.allow("alice") {
		t.Fatalf("alice 2nd: should be denied (her bucket empty)")
	}
	if !r.allow("bob") {
		t.Fatalf("bob 1st: should be allowed (his own bucket)")
	}
	if r.stats() != 2 {
		t.Errorf("stats=%d want 2", r.stats())
	}
}

func TestRateLimiter_NilAlwaysAllows(t *testing.T) {
	var r *rateLimiter
	for i := 0; i < 100; i++ {
		if !r.allow("anyone") {
			t.Fatal("nil rate limiter must always allow")
		}
	}
}

// Pre-fix, an empty key was treated as "always allow" — an agent
// envelope missing its agent_id (or whatever rate-limit-key-by
// selects) bypassed rate limiting entirely. Now empty keys collapse
// to the "_unknown" bucket and share its limit.
func TestRateLimiter_EmptyKeyIsBucketed(t *testing.T) {
	r := newRateLimiter(0.0001, 1) // 1 token, ~no refill
	if !r.allow("") {
		t.Fatalf("first empty-key call should consume the bucket and allow")
	}
	if r.allow("") {
		t.Fatalf("second empty-key call must be DENIED — pre-fix bypass class")
	}
	// And a real key should still have its own bucket.
	if !r.allow("alice") {
		t.Fatalf("alice's bucket should be independent of _unknown")
	}
	if r.stats() != 2 {
		t.Errorf("stats=%d want 2 (one _unknown, one alice)", r.stats())
	}
}
