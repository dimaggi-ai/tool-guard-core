package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
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

func TestEscalationStore_ResolutionUsesOneDeadlineTimestamp(t *testing.T) {
	base := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	clock := base
	s := newEscalationStore()
	s.now = func() time.Time { return clock }

	before := s.add(envFor("before-deadline"), decisionFor(domain.DecisionEscalated), 15)
	resolutionReads := 0
	s.now = func() time.Time {
		resolutionReads++
		if resolutionReads == 1 {
			return before.ExpiresAt.Add(-time.Nanosecond)
		}
		return before.ExpiresAt
	}
	resolved, ok, err := s.resolveAudited("before-deadline", "operator", "verified", true, nil)
	if err != nil || !ok || resolved.State != EscApproved || resolved.ResolvedAt == nil {
		t.Fatalf("before-deadline resolution = %#v, ok=%v err=%v", resolved, ok, err)
	}
	if resolutionReads != 1 {
		t.Fatalf("resolution read clock %d times, want exactly 1", resolutionReads)
	}
	if !resolved.ResolvedAt.Equal(before.ExpiresAt.Add(-time.Nanosecond)) || !resolved.ResolvedAt.Before(resolved.ExpiresAt) {
		t.Fatalf("resolved_at=%v expires_at=%v, want captured time strictly before deadline", resolved.ResolvedAt, resolved.ExpiresAt)
	}

	clock = base
	s.now = func() time.Time { return clock }
	atDeadline := s.add(envFor("at-deadline"), decisionFor(domain.DecisionEscalated), 15)
	deadlineReads := 0
	s.now = func() time.Time {
		deadlineReads++
		return atDeadline.ExpiresAt
	}
	callbackCalled := false
	rejected, ok, err := s.resolveAudited(
		"at-deadline", "operator", "too late", true,
		func(*Escalation) error {
			callbackCalled = true
			return nil
		},
	)
	if !errors.Is(err, errEscalationPastDue) || ok || callbackCalled || deadlineReads != 1 {
		t.Fatalf("deadline resolution = %#v, ok=%v err=%v callback=%v clock_reads=%d; want one read and rejection before audit", rejected, ok, err, callbackCalled, deadlineReads)
	}
	if rejected == nil || rejected.State != EscPending || rejected.ResolvedAt != nil {
		t.Fatalf("deadline rejection mutated state: %#v", rejected)
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

func TestEscalationStoreAttachResolutionReceipt(t *testing.T) {
	store := newEscalationStore()
	store.add(envFor("env-receipt"), decisionFor(domain.DecisionEscalated), 15)
	resolved, ok := store.resolve("env-receipt", "dba", "approved", true)
	if !ok {
		t.Fatal("resolve failed")
	}
	receipt := &audit.DecisionReceipt{ReceiptVersion: audit.ReceiptVersion, TraceID: "trace-resolution"}
	updated := store.attachResolutionReceipt(resolved.ID, resolved.State, *resolved.ResolvedAt, receipt)
	if updated == nil || updated.ResolutionReceipt != receipt {
		t.Fatalf("updated escalation = %+v, want attached receipt", updated)
	}
	if persisted := store.get(resolved.ID); persisted == nil || persisted.ResolutionReceipt != receipt {
		t.Fatalf("receipt was not persisted: %+v", persisted)
	}
}

func TestEscalationStoreRejectsStaleResolutionReceiptAfterIDReuse(t *testing.T) {
	store := newEscalationStore()
	store.maxEntries = 1
	store.add(envFor("reused"), decisionFor(domain.DecisionEscalated), 15)
	old, _ := store.resolve("reused", "dba", "approved", true)
	store.add(envFor("other"), decisionFor(domain.DecisionEscalated), 15)
	store.resolve("other", "dba", "denied", false)
	store.add(envFor("reused"), decisionFor(domain.DecisionEscalated), 15)

	receipt := &audit.DecisionReceipt{ReceiptVersion: audit.ReceiptVersion, TraceID: "stale"}
	if got := store.attachResolutionReceipt("reused", old.State, *old.ResolvedAt, receipt); got != nil {
		t.Fatalf("stale receipt attached to reused ID: %+v", got)
	}
	if current := store.get("reused"); current == nil || current.State != EscPending || current.ResolutionReceipt != nil {
		t.Fatalf("new escalation changed by stale attachment: %+v", current)
	}
}

func TestEscalationStoreResolutionReceiptRaceSafe(t *testing.T) {
	store := newEscalationStore()
	const entries = 50
	for i := 0; i < entries; i++ {
		store.add(envFor(receiptEscalationID(i)), decisionFor(domain.DecisionEscalated), 15)
	}
	var wait sync.WaitGroup
	for i := 0; i < entries; i++ {
		i := i
		wait.Add(2)
		go func() {
			defer wait.Done()
			id := receiptEscalationID(i)
			if resolved, ok := store.resolve(id, "approver", "ok", true); ok {
				store.attachResolutionReceipt(id, resolved.State, *resolved.ResolvedAt, &audit.DecisionReceipt{ReceiptVersion: audit.ReceiptVersion})
			}
		}()
		go func() {
			defer wait.Done()
			_ = store.get(receiptEscalationID(i))
			_ = store.list()
		}()
	}
	wait.Wait()
}

func receiptEscalationID(index int) string {
	return string(rune('a'+index%26)) + string(rune('0'+index/26))
}

func TestEscalationStore_TimeoutDefaultsTo15Min(t *testing.T) {
	s := newEscalationStore()
	e := s.add(envFor("env-4"), decisionFor(domain.DecisionEscalated), 0)
	gap := e.ExpiresAt.Sub(e.CreatedAt)
	if gap < 14*time.Minute || gap > 16*time.Minute {
		t.Errorf("default timeout = %s, want ~15min", gap)
	}
}
