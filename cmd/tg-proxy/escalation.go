package main

import (
	"errors"
	"sync"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// EscalationState is the lifecycle state of a pending escalation.
type EscalationState string

const (
	EscPending  EscalationState = "pending"
	EscApproved EscalationState = "approved"
	EscDenied   EscalationState = "denied"
	EscExpired  EscalationState = "expired"
	// EscIndeterminate means a terminal audit record may exist but its
	// durability and the corresponding state transition could not be proven.
	// Operators must reconcile the log; neither approval nor denial is granted.
	EscIndeterminate EscalationState = "indeterminate"
)

var errEscalationPastDue = errors.New("escalation is past due")

// Escalation is one human-review decision and its lifecycle state.
type Escalation struct {
	ID             string                  `json:"id"` // envelope_id, reused
	State          EscalationState         `json:"state"`
	CreatedAt      time.Time               `json:"created_at"`
	ExpiresAt      time.Time               `json:"expires_at"`
	ResolvedAt     *time.Time              `json:"resolved_at,omitempty"`
	Approver       string                  `json:"approver,omitempty"`
	ApproverReason string                  `json:"approver_reason,omitempty"`
	Envelope       domain.ActionEnvelope   `json:"envelope"`
	Decision       domain.EvaluationResult `json:"decision"`
}

// escalationStore is the proxy-level pending-escalation registry.
// Backed by an in-memory map with a mutex. For v0.1.0 this lives in
// the proxy's process; a restart loses pending state (the agent will
// re-poll, see the entry missing, and treat it as expired/deny).
//
// Bounded by maxEntries: when full, add() evicts the oldest expired
// entries before inserting. Stops a noisy agent from minting
// envelope IDs forever and OOM-ing the proxy.
type escalationStore struct {
	mu         sync.Mutex
	entries    map[string]*Escalation
	maxEntries int
	now        func() time.Time
}

// defaultEscalationMaxEntries caps the in-memory pending+resolved
// snapshot. At 10k entries × ~2 KB each ≈ 20 MB heap.
const defaultEscalationMaxEntries = 10_000

func newEscalationStore() *escalationStore {
	return &escalationStore{
		entries:    make(map[string]*Escalation),
		maxEntries: defaultEscalationMaxEntries,
		now:        time.Now,
	}
}

func (s *escalationStore) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// evictOldestResolvedLocked drops the oldest resolved entry (any
// terminal state). Returns true if an entry was evicted, false if the
// map contains only pending entries (caller decides whether to refuse
// the insert to keep the hard cap honest). Caller must hold s.mu.
func (s *escalationStore) evictOldestResolvedLocked() bool {
	var (
		oldestID string
		oldest   time.Time
	)
	for id, e := range s.entries {
		if e.State == EscPending {
			continue
		}
		t := e.CreatedAt
		if e.ResolvedAt != nil {
			t = *e.ResolvedAt
		}
		if oldestID == "" || t.Before(oldest) {
			oldestID = id
			oldest = t
		}
	}
	if oldestID == "" {
		return false
	}
	delete(s.entries, oldestID)
	return true
}

// add registers a new pending escalation. Caller passes the timeout
// in minutes (from EffectConfig.TimeoutMinutes or a default).
func (s *escalationStore) add(envelope *domain.ActionEnvelope, decision *domain.EvaluationResult, timeoutMinutes int) *Escalation {
	if timeoutMinutes < 1 {
		timeoutMinutes = 15
	}
	now := s.currentTime()
	e := &Escalation{
		ID:        envelope.EnvelopeID,
		State:     EscPending,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(timeoutMinutes) * time.Minute),
		Envelope:  *envelope,
		Decision:  *decision,
	}
	s.mu.Lock()
	// Reject the existing-ID collision case explicitly. envelope_id
	// is treated as the escalation ID by the proxy. If a colliding
	// envelope_id came back to us, the agent polling against this ID
	// would see the OLD entry's state — including a previously-
	// approved entry. That's an authorization-confusion bypass: a
	// compromised agent reuses a known-approved envelope_id with a
	// fresh malicious envelope and the new request reads "approved".
	// Return nil so the caller routes this as a collision error to
	// the agent instead of escalating.
	if _, exists := s.entries[e.ID]; exists {
		s.mu.Unlock()
		return nil
	}
	// At cap: prefer to evict an oldest resolved entry. If the map
	// is full of only PENDING entries the cap is hard — refuse to
	// add. This is a hostile-input bound: a stuck approval pipeline
	// could fill the store with pending entries and an attacker
	// could otherwise force unbounded memory growth by spamming
	// escalations the operator hasn't approved or denied. Returning
	// nil from this path tells the caller to log + reject (the
	// agent will receive a 503 or similar — better than OOM).
	if len(s.entries) >= s.maxEntries {
		if !s.evictOldestResolvedLocked() {
			s.mu.Unlock()
			return nil
		}
	}
	s.entries[e.ID] = e
	s.mu.Unlock()
	return e
}

func (s *escalationStore) get(id string) *Escalation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		ec := *e
		return &ec
	}
	return nil
}

func (s *escalationStore) resolve(id, approver, reason string, approved bool) (*Escalation, bool) {
	e, ok, _ := s.resolveAudited(id, approver, reason, approved, nil)
	return e, ok
}

// resolveAudited prepares a terminal state, invokes beforeCommit while the
// entry is still pending, and publishes the state only if that callback
// succeeds. Holding the store lock across the callback serializes competing
// approvals for the same entry. The callback must not call back into the
// escalation store.
func (s *escalationStore) resolveAudited(
	id, approver, reason string,
	approved bool,
	beforeCommit func(*Escalation) error,
) (*Escalation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, false, nil
	}
	if e.State != EscPending {
		ec := *e
		return &ec, false, nil
	}
	now := s.currentTime()
	// The reaper may leave a due entry pending when it can prove that the
	// expiry audit record was not written. Pending is an audit-recovery state
	// in that case, not a renewed authorization window: never let a late human
	// resolution bypass the original expiry deadline.
	if !now.Before(e.ExpiresAt) {
		ec := *e
		return &ec, false, errEscalationPastDue
	}
	candidate := *e
	candidate.ResolvedAt = &now
	candidate.Approver = approver
	candidate.ApproverReason = reason
	if approved {
		candidate.State = EscApproved
	} else {
		candidate.State = EscDenied
	}
	if beforeCommit != nil {
		if err := beforeCommit(&candidate); err != nil {
			if errors.Is(err, errAuditStateIndeterminate) || errors.Is(err, errAuditRecordCommitted) {
				candidate.State = EscIndeterminate
				*e = candidate
				indeterminate := *e
				return &indeterminate, false, err
			}
			current := *e
			return &current, false, err
		}
	}
	*e = candidate
	ec := *e
	return &ec, true, nil
}

type escalationExpiryFailure struct {
	Escalation Escalation
	Err        error
}

// reapExpiredAudited prepares each due expiration, invokes beforeCommit while
// the entry is still pending, and publishes expired only after the audit
// transition succeeds. An ambiguous terminal write becomes indeterminate;
// a proven pre-write failure leaves the entry pending for operator recovery.
func (s *escalationStore) reapExpiredAudited(
	beforeCommit func(*Escalation) error,
) ([]Escalation, []escalationExpiryFailure) {
	now := s.currentTime()
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		out      []Escalation
		failures []escalationExpiryFailure
	)
	for _, e := range s.entries {
		if e.State == EscPending && !now.Before(e.ExpiresAt) {
			candidate := *e
			candidate.State = EscExpired
			t := now
			candidate.ResolvedAt = &t
			if beforeCommit != nil {
				if err := beforeCommit(&candidate); err != nil {
					if errors.Is(err, errAuditStateIndeterminate) || errors.Is(err, errAuditRecordCommitted) {
						candidate.State = EscIndeterminate
						*e = candidate
					}
					failures = append(failures, escalationExpiryFailure{Escalation: *e, Err: err})
					continue
				}
			}
			*e = candidate
			out = append(out, *e)
		}
	}
	return out, failures
}

// reapExpired preserves the store-only helper used by unit tests and callers
// that do not own an audit writer.
func (s *escalationStore) reapExpired() []Escalation {
	expired, _ := s.reapExpiredAudited(nil)
	return expired
}

// list returns a snapshot of all entries (pending + resolved). Used
// by GET /escalations for operator dashboards.
func (s *escalationStore) list() []Escalation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Escalation, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, *e)
	}
	return out
}
