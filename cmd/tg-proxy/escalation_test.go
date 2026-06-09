package main

import (
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func envFor(id string) *domain.ActionEnvelope {
	return &domain.ActionEnvelope{
		EnvelopeID: id,
		AgentID:    "alice",
		ToolName:   "query",
	}
}

func decisionFor(s domain.Decision) *domain.EvaluationResult {
	return &domain.EvaluationResult{
		Decision:    s,
		ActionTaken: domain.ActionTaken(s),
	}
}

func TestEscalationStore_AddAndGet(t *testing.T) {
	s := newEscalationStore()
	env := envFor("env-1")
	e := s.add(env, decisionFor(domain.DecisionEscalated), 15)
	if e.State != EscPending {
		t.Errorf("state=%s want pending", e.State)
	}
	if e.ID != "env-1" {
		t.Errorf("id=%s want env-1", e.ID)
	}
	got := s.get("env-1")
	if got == nil || got.State != EscPending {
		t.Errorf("get returned %+v", got)
	}
	if s.get("does-not-exist") != nil {
		t.Errorf("nonexistent get should return nil")
	}
}

func TestEscalationStore_Approve(t *testing.T) {
	s := newEscalationStore()
	s.add(envFor("env-1"), decisionFor(domain.DecisionEscalated), 15)
	e, ok := s.resolve("env-1", "dba-on-call", "validated against runbook", true)
	if !ok || e.State != EscApproved {
		t.Errorf("approve failed: ok=%v e=%+v", ok, e)
	}
	if e.Approver != "dba-on-call" {
		t.Errorf("approver lost: %q", e.Approver)
	}
	// Re-approve must be a conflict.
	e2, ok := s.resolve("env-1", "other", "", true)
	if ok {
		t.Errorf("second resolve should not succeed; e=%+v", e2)
	}
	if e2 == nil || e2.State != EscApproved {
		t.Errorf("re-resolve should still report current state: %+v", e2)
	}
}

func TestEscalationStore_Deny(t *testing.T) {
	s := newEscalationStore()
	s.add(envFor("env-2"), decisionFor(domain.DecisionEscalated), 15)
	e, ok := s.resolve("env-2", "dba", "policy violation in spirit", false)
	if !ok || e.State != EscDenied {
		t.Errorf("deny failed: ok=%v e=%+v", ok, e)
	}
}

func TestEscalationStore_ReaperExpires(t *testing.T) {
	s := newEscalationStore()
	env := envFor("env-3")
	e := s.add(env, decisionFor(domain.DecisionEscalated), 15)
	// Force expiry in the past.
	s.mu.Lock()
	s.entries["env-3"].ExpiresAt = time.Now().Add(-1 * time.Second)
	s.mu.Unlock()
	expired := s.reapExpired()
	if len(expired) != 1 {
		t.Errorf("reaper expired %d, want 1", len(expired))
	}
	got := s.get("env-3")
	if got == nil || got.State != EscExpired {
		t.Errorf("post-reap state = %+v, want expired", got)
	}
	// Trying to resolve an already-expired entry is a no-op.
	_, ok := s.resolve(e.ID, "late-arrival", "", true)
	if ok {
		t.Errorf("resolving expired should not succeed")
	}
}

func TestEscalationStore_List(t *testing.T) {
	s := newEscalationStore()
	s.add(envFor("a"), decisionFor(domain.DecisionEscalated), 15)
	s.add(envFor("b"), decisionFor(domain.DecisionEscalated), 15)
	s.add(envFor("c"), decisionFor(domain.DecisionEscalated), 15)
	s.resolve("b", "approver", "", true)
	list := s.list()
	if len(list) != 3 {
		t.Errorf("list len=%d want 3", len(list))
	}
}

func TestEscalationStore_TimeoutDefaultsTo15Min(t *testing.T) {
	s := newEscalationStore()
	e := s.add(envFor("env-4"), decisionFor(domain.DecisionEscalated), 0)
	gap := e.ExpiresAt.Sub(e.CreatedAt)
	if gap < 14*time.Minute || gap > 16*time.Minute {
		t.Errorf("default timeout = %s, want ~15min", gap)
	}
}
