package main

import (
	"sync"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// Velocity tracking closes the amount-fragmentation bypass class
// documented in docs/battle-test-results.md: an agent that splits one
// large monetary action into many small ones, each under a per-call cap.
//
// The envelope schema already carries context.verified.agent_velocity.*
// (monetary sum/count over 1h and 24h), and the engine already flattens
// those into fields a normal `gt` rule can read. What was missing was
// anything that COMPUTES them. This tracker does: it keeps a per-key
// sliding window of monetary actions (exactly like the rate limiter
// keeps per-key token buckets), and the evaluate handler injects the
// aggregates into the envelope before evaluation.
//
// A policy then closes the bypass with an ordinary rule, e.g.:
//
//	field: context.verified.agent_velocity.monetary_sum_1h
//	operator: gt
//	value: 5000            # deny once the 1h refund total would cross $5k
//
// The proxy NEVER overwrites a caller-supplied agent_velocity block — a
// deployment with a real ledger stays authoritative; the in-memory
// tracker is the out-of-the-box default for deployments that have none.

// velocityEvent is one recorded monetary action.
type velocityEvent struct {
	at     time.Time
	amount float64
}

// velocityMaxEventsPerKey bounds a single hot key between 24h prunes so
// a runaway agent cannot grow one window without limit.
const velocityMaxEventsPerKey = 20_000

// velocityWindow holds recent monetary events for one key.
type velocityWindow struct {
	mu     sync.Mutex
	events []velocityEvent
	last   time.Time
}

// pruneLocked drops events older than 24h and enforces the hard cap.
// Caller holds w.mu.
func (w *velocityWindow) pruneLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	i := 0
	for i < len(w.events) && w.events[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		w.events = append(w.events[:0], w.events[i:]...)
	}
	if len(w.events) > velocityMaxEventsPerKey {
		drop := len(w.events) - velocityMaxEventsPerKey
		w.events = append(w.events[:0], w.events[drop:]...)
	}
}

// aggregate returns sum/count over the trailing 1h and 24h of PAST
// events (not including any prospective call).
func (w *velocityWindow) aggregate(now time.Time) (sum1h float64, count1h int, sum24h float64, count24h int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last = now
	w.pruneLocked(now)
	cut1h := now.Add(-time.Hour)
	for _, e := range w.events {
		sum24h += e.amount
		count24h++
		if !e.at.Before(cut1h) {
			sum1h += e.amount
			count1h++
		}
	}
	return sum1h, count1h, sum24h, count24h
}

// record appends a monetary action (only executed/allowed calls should
// be recorded so denied attempts don't inflate the window).
func (w *velocityWindow) record(now time.Time, amount float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, velocityEvent{at: now, amount: amount})
	w.last = now
	w.pruneLocked(now)
}

// velocityTracker is the proxy-level keyed window store. Bounded and
// idle-evicted exactly like rateLimiter so a churning key space
// (session_id) cannot grow memory without limit.
type velocityTracker struct {
	mu        sync.Mutex
	windows   map[string]*velocityWindow
	idleEvict time.Duration
	maxKeys   int
}

func newVelocityTracker() *velocityTracker {
	return &velocityTracker{
		windows:   make(map[string]*velocityWindow),
		idleEvict: defaultIdleEvict,
		maxKeys:   defaultRateLimitMaxKeys,
	}
}

// sweepIdleLocked drops windows untouched for longer than idleEvict.
// Caller holds v.mu.
func (v *velocityTracker) sweepIdleLocked() {
	cutoff := time.Now().Add(-v.idleEvict)
	for k, w := range v.windows {
		w.mu.Lock()
		last := w.last
		w.mu.Unlock()
		if last.Before(cutoff) {
			delete(v.windows, k)
		}
	}
}

// windowFor returns the window for a key, creating it if needed. An empty
// key shares a single "_unknown" bucket so a client cannot dodge
// velocity accounting by omitting the key field; same defence as the rate
// limiter.
func (v *velocityTracker) windowFor(key string) *velocityWindow {
	if v == nil {
		return nil
	}
	if key == "" {
		key = "_unknown"
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	w, ok := v.windows[key]
	if !ok {
		if len(v.windows) >= v.maxKeys {
			v.sweepIdleLocked()
		}
		w = &velocityWindow{last: time.Now()}
		v.windows[key] = w
	}
	return w
}

// stats returns the number of distinct keys tracked. Exposed via /metrics.
func (v *velocityTracker) stats() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.windows)
}

// keyForEnvelope selects the tracking key from the envelope per the
// configured -velocity-key-by field.
func velocityKey(env *domain.ActionEnvelope, keyBy string) string {
	switch keyBy {
	case "session_id":
		return env.SessionID
	case "org_id":
		return env.OrgID
	default:
		return env.AgentID
	}
}
