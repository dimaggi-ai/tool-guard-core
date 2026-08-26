package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

func TestEscalationApproval_AuditRollbackFailureBecomesIndeterminate(t *testing.T) {
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
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"audit_append_failed"`) ||
		!strings.Contains(body, `"state":"indeterminate"`) {
		t.Fatalf("structured failure response missing error/indeterminate state: %s", rec.Body.String())
	}
	if !strings.Contains(body, "resubmitted with a fresh envelope ID") ||
		!strings.Contains(body, "do not retry this escalation ID") ||
		strings.Contains(body, "wait for /readyz") {
		t.Fatalf("structured failure response has an inaccurate recovery hint: %s", body)
	}
	indeterminate := p.escalations.get(id)
	if indeterminate == nil || indeterminate.State != EscIndeterminate || indeterminate.ResolvedAt == nil {
		t.Fatalf("failed rollback state = %#v, want indeterminate", indeterminate)
	}
	if fault.writeCalls != 1 || !p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf(
			"audit failure state: writes=%d poisoned=%v failures=%d, want 1/true/1",
			fault.writeCalls, p.auditPoisoned, p.auditFailureCount.Load(),
		)
	}
}

func TestEscalationApproval_FullWriteErrorRollbackFailureBecomesIndeterminate(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	id := "approval-full-write-error"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	fault := &faultInjectAuditFile{
		auditLogFile:             p.auditLog,
		fullWriteErrorsRemaining: 1,
		failTruncate:             true,
	}
	p.auditLog = fault

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"state":"indeterminate"`) {
		t.Fatalf("full-write error response = %d %s, want 503 indeterminate", rec.Code, rec.Body.String())
	}
	if got := p.escalations.get(id); got == nil || got.State != EscIndeterminate {
		t.Fatalf("full-write error state = %#v, want indeterminate", got)
	}
	if fault.writeCalls != 1 || !p.auditPoisoned {
		t.Fatalf("full-write error audit state: writes=%d poisoned=%v, want 1/true", fault.writeCalls, p.auditPoisoned)
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].ActionTaken != domain.ActionAllowed {
		t.Fatalf("full-write error trace = %#v, want one possibly-written approval", traces)
	}
}

func TestEscalationResolution_AlwaysSyncsAndRollsBackBeforePublishingState(t *testing.T) {
	for _, syncMode := range []string{"none", "interval"} {
		for _, action := range []string{"approve", "deny"} {
			t.Run(syncMode+"/"+action, func(t *testing.T) {
				p := newOperationalTestProxy(t, nil, false)
				p.failClosed = false // let /readyz isolate audit readiness in this test
				p.approverToken = "secret"
				p.auditSyncMode = syncMode
				p.auditSyncEvery = 10 // first interval append is not a normal boundary
				id := syncMode + "-" + action + "-sync-failure"
				if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
					t.Fatal("seed escalation failed")
				}
				fault := &faultInjectAuditFile{
					auditLogFile:          p.auditLog,
					syncFailuresRemaining: 1,
				}
				p.auditLog = fault

				failed := resolveEscalationRequest(t, p, id, action)
				if failed.Code != http.StatusServiceUnavailable {
					t.Fatalf("resolution status = %d, want 503 after failed forced sync; body=%s", failed.Code, failed.Body.String())
				}
				pending := p.escalations.get(id)
				if pending == nil || pending.State != EscPending || pending.ResolvedAt != nil || pending.Approver != "" {
					t.Fatalf("state after rolled-back sync failure = %#v, want unchanged pending escalation", pending)
				}
				if fault.writeCalls != 1 || fault.syncCalls != 2 || p.auditPoisoned || p.auditAppendSeq != 0 || p.lastHash != "" {
					t.Fatalf(
						"rollback state: writes=%d syncs=%d poisoned=%v seq=%d hash=%q, want 1/2/false/0/empty",
						fault.writeCalls, fault.syncCalls, p.auditPoisoned, p.auditAppendSeq, p.lastHash,
					)
				}
				if traces := readOperationalTraces(t, p); len(traces) != 0 {
					t.Fatalf("rolled-back resolution left terminal traces: %#v", traces)
				}
				readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
				readyRec := httptest.NewRecorder()
				p.readyz(readyRec, readyReq)
				if readyRec.Code != http.StatusOK {
					t.Fatalf("readyz status = %d, want 200 after proven rollback; body=%s", readyRec.Code, readyRec.Body.String())
				}

				retried := resolveEscalationRequest(t, p, id, action)
				if retried.Code != http.StatusOK {
					t.Fatalf("retry status = %d, want 200 after transient sync failure; body=%s", retried.Code, retried.Body.String())
				}
				wantState := EscApproved
				if action == "deny" {
					wantState = EscDenied
				}
				if resolved := p.escalations.get(id); resolved == nil || resolved.State != wantState {
					t.Fatalf("retried resolution = %#v, want %s", resolved, wantState)
				}
				if fault.syncCalls != 4 {
					t.Fatalf("sync calls after durable retry = %d, want 4 (failed barrier, rollback, read, retry barrier)", fault.syncCalls)
				}
			})
		}
	}
}

func TestEscalationApproval_FullWriteRollbackFailureBecomesIndeterminate(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	p.auditSyncMode = "every"
	id := "approval-indeterminate"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	fault := &faultInjectAuditFile{
		auditLogFile:          p.auditLog,
		syncFailuresRemaining: 1,
		failTruncate:          true,
	}
	p.auditLog = fault

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolution status = %d, want 503 for indeterminate durability; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"state":"indeterminate"`) ||
		!strings.Contains(rec.Body.String(), "resubmitted with a fresh envelope ID") {
		t.Fatalf("indeterminate response lacks state/recovery guidance: %s", rec.Body.String())
	}
	indeterminate := p.escalations.get(id)
	if indeterminate == nil || indeterminate.State != EscIndeterminate || indeterminate.ResolvedAt == nil {
		t.Fatalf("state after failed full-write rollback = %#v, want indeterminate", indeterminate)
	}
	if fault.writeCalls != 1 || !p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf("uncertain audit state: writes=%d poisoned=%v failures=%d, want 1/true/1", fault.writeCalls, p.auditPoisoned, p.auditFailureCount.Load())
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].ActionTaken != domain.ActionAllowed {
		t.Fatalf("uncertain terminal trace = %#v, want one possibly-written allowed record", traces)
	}

	restarted := newOperationalTestProxy(t, nil, false)
	restarted.approverToken = "secret"
	oldRetry := resolveEscalationRequest(t, restarted, id, "approve")
	if oldRetry.Code != http.StatusNotFound {
		t.Fatalf("old escalation after restart = %d, want 404; body=%s", oldRetry.Code, oldRetry.Body.String())
	}
	freshID := id + "-resubmitted"
	if e := restarted.escalations.add(envFor(freshID), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed fresh escalation failed")
	}
	if fresh := resolveEscalationRequest(t, restarted, freshID, "approve"); fresh.Code != http.StatusOK {
		t.Fatalf("fresh resubmitted escalation status = %d, want 200; body=%s", fresh.Code, fresh.Body.String())
	}
}

func TestEscalationApproval_DurableRotationBarrierPrecedesApproval(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	p.auditSyncMode = "none"
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "rotation-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	p.auditRotateBytes = 1
	id := "approval-durable-rotation"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	directorySyncCalls := 0
	platformDirectorySync := p.auditRotation.syncDirectory
	p.auditRotation.syncDirectory = func(path string) error {
		directorySyncCalls++
		return platformDirectorySync(path)
	}

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotating approval status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if directorySyncCalls != 1 {
		t.Fatalf("platform directory barriers = %d, want 1", directorySyncCalls)
	}
	if _, err := os.Stat(p.auditPath + ".1"); err != nil {
		t.Fatalf("rotated audit file: %v", err)
	}
	if err := p.verifyFullAuditChain(); err != nil {
		t.Fatalf("rotated approval chain: %v", err)
	}
	if got := p.escalations.get(id); got == nil || got.State != EscApproved {
		t.Fatalf("rotating approval state = %#v, want approved", got)
	}
}

func TestOrdinaryRotationBarrierFailurePoisonsBeforeLaterApproval(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("ordinary-rotation", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0),
	}, false)
	p.auditSyncMode = "none"
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "ordinary-rotation-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	p.auditRotateBytes = 1
	directorySyncCalls := 0
	p.auditRotation.syncDirectory = func(string) error {
		directorySyncCalls++
		return errors.New("forced prior directory sync failure")
	}

	status, result := evaluateOperational(t, p, "ordinary-before-approval", 100)
	if status != http.StatusOK || result.ActionTaken != domain.ActionDenied {
		t.Fatalf("ordinary evaluation = %d/%s, want 200/denied fail-closed", status, result.ActionTaken)
	}
	if directorySyncCalls != 1 || !p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf(
			"ordinary barrier state: calls=%d poisoned=%v failures=%d, want 1/true/1",
			directorySyncCalls, p.auditPoisoned, p.auditFailureCount.Load(),
		)
	}
	readyRec := httptest.NewRecorder()
	p.readyz(readyRec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after uncertain rotation = %d, want 503", readyRec.Code)
	}

	// A later approval must not repair or bypass the forgotten barrier merely
	// because its own append would stay below the next rotation threshold.
	p.auditRotateBytes = 1 << 30
	p.approverToken = "secret"
	id := "approval-after-prior-rotation-failure"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"state":"approved"`) {
		t.Fatalf("approval after uncertain rotation = %d %s, want 503 and no approval", rec.Code, rec.Body.String())
	}
	if directorySyncCalls != 1 {
		t.Fatalf("poisoned approval retried file operations: directory sync calls=%d, want 1", directorySyncCalls)
	}
	for _, path := range p.auditCandidatesNewestFirst() {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read audit candidate %s: %v", path, err)
		}
		if strings.Contains(string(raw), "ordinary-before-approval") {
			t.Fatalf("failed evaluation reached audit candidate %s: %s", path, raw)
		}
	}
	if err := p.verifyFullAuditChain(); err != nil {
		t.Fatalf("rotation set after failed evaluation: %v", err)
	}
}

func TestOrdinaryRotationCloseFailurePoisonsUncertainWriter(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "close-failure-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	fault := &faultInjectAuditFile{
		auditLogFile:           p.auditLog,
		closeFailuresRemaining: 1,
	}
	p.auditLog = fault
	p.auditRotateBytes = 1

	err := p.appendTrace(&domain.DecisionTrace{
		TraceID:     "ordinary-close-failure",
		Decision:    domain.DecisionDenied,
		ActionTaken: domain.ActionDenied,
	})
	if !errors.Is(err, errAuditWriterPoisoned) || errors.Is(err, errAuditStateIndeterminate) {
		t.Fatalf("rotation close failure = %v, want poisoned writer without current-trace indeterminacy", err)
	}
	if !p.auditPoisoned {
		t.Fatal("rotation close failure did not poison writer")
	}
}

func TestOrdinaryRotationRenameFailureAfterClosePoisonsWriter(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "rename-failure-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	p.auditRotateBytes = 1
	p.auditRotation.rename = func(string, string) error { return errors.New("forced rename failure") }

	err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "must-not-write-after-rename-failure",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	})
	if !errors.Is(err, errAuditWriterPoisoned) {
		t.Fatalf("rotation rename failure = %v, want poisoned writer", err)
	}
	if !p.auditPoisoned {
		t.Fatal("rotation rename failure did not poison writer")
	}
	ready := httptest.NewRecorder()
	p.readyz(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after rename failure = %d, want 503", ready.Code)
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].TraceID != "rename-failure-seed" {
		t.Fatalf("rename failure wrote current trace: %#v", traces)
	}
}

func TestEscalationApproval_PreRotationBarrierFailureRemainsUnapproved(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	p.approverToken = "secret"
	p.auditSyncMode = "none"
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "failed-approval-rotation-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	p.auditRotateBytes = 1
	p.auditRotation.syncDirectory = func(string) error { return errors.New("forced directory sync failure") }
	id := "approval-rotation-indeterminate"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}

	rec := resolveEscalationRequest(t, p, id, "approve")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"state":"pending"`) {
		t.Fatalf("rotation barrier response = %d %s, want 503 pending", rec.Code, rec.Body.String())
	}
	if got := p.escalations.get(id); got == nil || got.State != EscPending {
		t.Fatalf("rotation barrier state = %#v, want pending", got)
	}
	if !p.auditPoisoned {
		t.Fatal("rotation barrier failure did not poison the audit writer")
	}
	if _, err := os.Stat(p.auditPath + ".1"); err != nil {
		t.Fatalf("uncertain rotated audit file: %v", err)
	}
}

func TestEscalationExpiry_PreRotationFailureLeavesPendingWithoutTerminalTrace(t *testing.T) {
	p := newOperationalTestProxy(t, nil, false)
	if err := p.appendTrace(&domain.DecisionTrace{
		TraceID:  "expiry-rotation-seed",
		Decision: domain.DecisionDenied, ActionTaken: domain.ActionDenied,
	}); err != nil {
		t.Fatalf("seed audit trace: %v", err)
	}
	p.auditRotateBytes = 1
	p.auditRotation.syncDirectory = func(string) error { return errors.New("forced expiry directory sync failure") }
	id := "expiry-before-failed-rotation"
	if e := p.escalations.add(envFor(id), decisionFor(domain.DecisionEscalated), 15); e == nil {
		t.Fatal("seed escalation failed")
	}
	p.escalations.mu.Lock()
	p.escalations.entries[id].ExpiresAt = time.Now().Add(-time.Second)
	p.escalations.mu.Unlock()

	expired, failures := p.escalations.reapExpiredAudited(p.emitEscalationExpiry)
	if len(expired) != 0 || len(failures) != 1 {
		t.Fatalf("expiry results = %d expired/%d failures, want 0/1", len(expired), len(failures))
	}
	if got := p.escalations.get(id); got == nil || got.State != EscPending || got.ResolvedAt != nil {
		t.Fatalf("failed audited expiry state = %#v, want unresolved pending", got)
	}
	for _, path := range p.auditCandidatesNewestFirst() {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read audit candidate %s: %v", path, err)
		}
		if strings.Contains(string(raw), id) {
			t.Fatalf("failed expiry reached audit candidate %s: %s", path, raw)
		}
	}
	if !p.auditPoisoned {
		t.Fatal("uncertain expiry pre-rotation did not poison writer")
	}
}
