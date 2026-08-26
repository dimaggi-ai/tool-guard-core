package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func resolveEscalationRequest(t *testing.T, p *proxy, id, action string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(
		http.MethodPost,
		"/escalations/"+id+"/"+action,
		strings.NewReader(`{"approver":"operator","reason":"verified"}`),
	)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	p.escalationByID(rec, req)
	return rec
}

func TestEscalationResolution_AuditPrecedesTerminalState(t *testing.T) {
	tests := []struct {
		action       string
		wantState    EscalationState
		wantDecision domain.Decision
		wantAction   domain.ActionTaken
	}{
		{action: "approve", wantState: EscApproved, wantDecision: domain.DecisionAllowed, wantAction: domain.ActionAllowed},
		{action: "deny", wantState: EscDenied, wantDecision: domain.DecisionDenied, wantAction: domain.ActionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			p := newOperationalTestProxy(t, nil, false)
			p.approverToken = "secret"
			id := "audited-" + tt.action
			if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
				t.Fatal("seed escalation failed")
			}

			rec := resolveEscalationRequest(t, p, id, tt.action)
			if rec.Code != http.StatusOK {
				t.Fatalf("resolution status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			resolved := p.escalations.get(id)
			if resolved == nil || resolved.State != tt.wantState || resolved.ResolvedAt == nil {
				t.Fatalf("resolved escalation = %#v, want state %q", resolved, tt.wantState)
			}
			traces := readOperationalTraces(t, p)
			if len(traces) != 1 || traces[0].Decision != tt.wantDecision || traces[0].ActionTaken != tt.wantAction {
				t.Fatalf("resolution audit traces = %#v, want one %s/%s record", traces, tt.wantDecision, tt.wantAction)
			}
		})
	}
}

func TestEscalationApproval_AuditRollbackFailureLeavesPending(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	id := "approval-audit-failure"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	fault := &faultInjectAuditFile{
		auditLogFile:         p.auditLog,
		shortWritesRemaining: 1,
		failTruncate:         true,
	}
	p.auditLog = fault

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolution status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	if !strings.Contains(rec.Body.String(), `"error":"audit_append_failed"`) ||
		!strings.Contains(rec.Body.String(), `"state":"pending"`) {
		t.Fatalf("structured failure response missing error/pending state: %s", rec.Body.String())
	}
	pending := p.escalations.get(id)
	if pending == nil || pending.State != EscPending || pending.ResolvedAt != nil || pending.Approver != "" {
		t.Fatalf("failed approval mutated escalation: %#v", pending)
	}
	if fault.writeCalls != 1 || !p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf(
			"audit failure state: writes=%d poisoned=%v failures=%d, want 1/true/1",
			fault.writeCalls, p.auditPoisoned, p.auditFailureCount.Load(),
		)
	}
}

func TestEscalationApproval_FullWriteSyncFailureKeepsAuditAndStateAligned(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	p.auditSyncMode = "every"
	id := "approval-sync-failure"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	fault := &faultInjectAuditFile{
		auditLogFile:          p.auditLog,
		syncFailuresRemaining: 1,
	}
	p.auditLog = fault

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("resolution status = %d, want 200 for a fully written record; body=%s", rec.Code, rec.Body.String())
	}
	approved := p.escalations.get(id)
	if approved == nil || approved.State != EscApproved {
		t.Fatalf("state after committed record sync warning = %#v, want approved", approved)
	}
	if fault.writeCalls != 1 || p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf(
			"sync warning state: writes=%d poisoned=%v failures=%d, want 1/false/1",
			fault.writeCalls, p.auditPoisoned, p.auditFailureCount.Load(),
		)
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].ActionTaken != domain.ActionAllowed {
		t.Fatalf("committed approval trace = %#v, want one allowed record", traces)
	}
}
