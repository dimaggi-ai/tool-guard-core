package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

func operationalPolicy(id string, mode domain.PolicyMode, effect domain.Effect, field string, value float64) domain.Policy {
	return domain.Policy{
		PolicyID: id,
		Name:     id,
		Version:  1,
		Status:   domain.PolicyStatusApproved,
		Mode:     mode,
		Scope:    domain.PolicyScope{ToolNames: []string{"issue_refund"}},
		Rules: []domain.Rule{{
			RuleID:     id + "-rule",
			Name:       id + " rule",
			Conditions: domain.Condition{Field: field, Operator: domain.OpGt, Value: value},
			Effect:     effect,
			EffectConfig: domain.EffectConfig{
				SuggestedResponse: "policy guidance must not survive an operational deny",
			},
			Citation: domain.Citation{DocumentID: "test", Excerpt: "operational shadow regression"},
		}},
	}
}

func newOperationalTestProxy(t *testing.T, policies []domain.Policy, trackVelocity bool) *proxy {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	p := &proxy{
		policies:             policies,
		auditLog:             auditLog,
		auditPath:            auditPath,
		defaultMode:          domain.PolicyModeEnforcement,
		failClosed:           true,
		maxJSONDepth:         32,
		auditSyncMode:        "none",
		auditSyncEvery:       1,
		escalations:          newEscalationStore(),
		escalationDefaultMin: 15,
		eval:                 engine.NewEvaluator(),
		startedAt:            time.Now().UTC(),
	}
	if trackVelocity {
		p.velocity = newVelocityTracker()
		p.velocityKeyBy = "agent_id"
	}
	return p
}

func evaluateOperational(t *testing.T, p *proxy, envelopeID string, amount float64) (int, domain.EvaluationResult) {
	return evaluateOperationalTool(t, p, envelopeID, "issue_refund", "monetary_outflow", amount)
}

func evaluateOperationalTool(t *testing.T, p *proxy, envelopeID, toolName, toolGroup string, amount float64) (int, domain.EvaluationResult) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"envelope_id": envelopeID,
		"agent_id":    "shadow-agent",
		"session_id":  "shadow-session",
		"org_id":      "shadow-org",
		"tool_name":   toolName,
		"tool_group":  toolGroup,
		"parameters":  map[string]any{"amount": amount},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	p.evaluate(rec, req)
	var result domain.EvaluationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response (status %d): %v; body=%s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, result
}

func readOperationalTraces(t *testing.T, p *proxy) []domain.DecisionTrace {
	t.Helper()
	if err := p.auditLog.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var traces []domain.DecisionTrace
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var trace domain.DecisionTrace
		if err := json.Unmarshal(line, &trace); err != nil {
			t.Fatalf("decode audit trace: %v; line=%s", err, line)
		}
		traces = append(traces, trace)
	}
	return traces
}

func assertOperationalDenyHasNoPolicyAttribution(t *testing.T, result domain.EvaluationResult) {
	t.Helper()
	if len(result.AppliedRuleResults) != 0 || result.AppliedPrimaryCitation != nil {
		t.Errorf("operational deny retained applied policy provenance: rules=%#v citation=%#v",
			result.AppliedRuleResults, result.AppliedPrimaryCitation)
	}
	if result.PrimaryCitation != nil || result.SuggestedResponse != "" {
		t.Errorf("operational deny retained policy attribution: citation=%#v guidance=%q",
			result.PrimaryCitation, result.SuggestedResponse)
	}
}

func TestProxy_AuditBindsEvaluatedAmountProvenance(t *testing.T) {
	tests := []struct {
		name             string
		parameters       any
		wantAmount       float64
		wantStatus       string
		wantNegativeZero bool
	}{
		{name: "sub-cent", parameters: map[string]any{"amount": 1.001}, wantAmount: 1.001, wantStatus: engine.AmountParseOK},
		{name: "malformed", parameters: map[string]any{"amount": map[string]any{"value": 100}}, wantAmount: 1e18, wantStatus: engine.AmountParseInvalidFailClosed},
		{name: "negative-zero-number", parameters: map[string]any{"amount": math.Copysign(0, -1)}, wantAmount: math.Copysign(0, -1), wantStatus: engine.AmountParseOK, wantNegativeZero: true},
		{name: "negative-zero-string", parameters: map[string]any{"amount": "-0"}, wantAmount: math.Copysign(0, -1), wantStatus: engine.AmountParseOK, wantNegativeZero: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newOperationalTestProxy(t, []domain.Policy{
				operationalPolicy("amount-provenance", domain.PolicyModeEnforcement, domain.EffectDeny, "amount", 0),
			}, false)
			body, err := json.Marshal(map[string]any{
				"envelope_id": "amount-" + tt.name,
				"agent_id":    "audit-agent",
				"session_id":  "audit-session",
				"org_id":      "audit-org",
				"tool_name":   "issue_refund",
				"tool_group":  "monetary_outflow",
				"parameters":  tt.parameters,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			p.evaluate(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
			}

			traces := readOperationalTraces(t, p)
			if len(traces) != 1 {
				t.Fatalf("audit trace count = %d, want 1", len(traces))
			}
			trace := traces[0]
			if trace.Amount != tt.wantAmount || trace.AmountParseStatus != tt.wantStatus {
				t.Fatalf("amount provenance = (%v, %q), want (%v, %q)", trace.Amount, trace.AmountParseStatus, tt.wantAmount, tt.wantStatus)
			}
			if math.Signbit(trace.Amount) != tt.wantNegativeZero {
				t.Fatalf("amount signbit = %v, want %v (amount=%v)", math.Signbit(trace.Amount), tt.wantNegativeZero, trace.Amount)
			}
			ok, err := audit.VerifyCanonicalTraceHash(&trace)
			if err != nil || !ok {
				t.Fatalf("canonical amount verification: ok=%v err=%v", ok, err)
			}
			raw, err := os.ReadFile(p.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			report, err := audit.VerifyChainFromReader(bytes.NewReader(raw))
			if err != nil || !report.Intact || report.Records != 1 {
				t.Fatalf("amount audit chain verification = %#v, err=%v", report, err)
			}

			if err := p.auditLog.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := &proxy{auditPath: p.auditPath, auditSyncMode: "none"}
			if err := restarted.openAuditLog(); err != nil {
				t.Fatalf("proxy restart after amount %q: %v", tt.name, err)
			}
			if restarted.lastHash != trace.TraceHash {
				t.Fatalf("recovered tail = %q, want %q", restarted.lastHash, trace.TraceHash)
			}
			if err := restarted.auditLog.Close(); err != nil {
				t.Fatal(err)
			}

			trace.Amount = math.Nextafter(trace.Amount, math.Inf(1))
			ok, err = audit.VerifyCanonicalTraceHash(&trace)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Fatal("sub-cent amount tamper did not break the audit hash")
			}
		})
	}
}

func TestProxy_ShadowGatingEffectsProceedWithoutEscalationRegistration(t *testing.T) {
	tests := []struct {
		name   string
		effect domain.Effect
	}{
		{"deny", domain.EffectDeny},
		{"escalate", domain.EffectEscalate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newOperationalTestProxy(t, []domain.Policy{
				operationalPolicy("shadow-"+tt.name, domain.PolicyModeShadow, tt.effect, "amount", 0),
			}, false)
			status, result := evaluateOperational(t, p, "shadow-"+tt.name, 100)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if result.ActionTaken != domain.ActionAllowedShadow {
				t.Fatalf("action_taken = %q, want allowed_shadow", result.ActionTaken)
			}
			if p.escalations.get("shadow-"+tt.name) != nil {
				t.Fatal("shadow effect created a pending escalation")
			}
			if p.allowCount.Load() != 1 || p.escalateCount.Load() != 0 {
				t.Errorf("applied-action counters: allow=%d escalate=%d, want 1/0", p.allowCount.Load(), p.escalateCount.Load())
			}
		})
	}
}

func TestProxy_ShadowProceedingActionIsRecordedForVelocity(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("shadow-deny", domain.PolicyModeShadow, domain.EffectDeny, "amount", 0),
		operationalPolicy("velocity-cap", domain.PolicyModeEnforcement, domain.EffectDeny,
			"context.verified.agent_velocity.monetary_sum_1h", 150),
	}, true)

	_, first := evaluateOperational(t, p, "velocity-first", 100)
	if first.ActionTaken != domain.ActionAllowedShadow {
		t.Fatalf("first action = %q, want allowed_shadow", first.ActionTaken)
	}
	_, second := evaluateOperational(t, p, "velocity-second", 100)
	if second.ActionTaken != domain.ActionDenied {
		t.Fatalf("second action = %q, want denied after the first proceeded amount was recorded", second.ActionTaken)
	}
}

func TestProxy_FlaggedActionIsRecordedForVelocity(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("flag", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0),
		operationalPolicy("velocity-cap", domain.PolicyModeEnforcement, domain.EffectDeny,
			"context.verified.agent_velocity.monetary_sum_1h", 150),
	}, true)

	_, first := evaluateOperational(t, p, "flagged-velocity-first", 100)
	if first.ActionTaken != domain.ActionFlagged {
		t.Fatalf("first action = %q, want flagged", first.ActionTaken)
	}
	_, second := evaluateOperational(t, p, "flagged-velocity-second", 100)
	if second.ActionTaken != domain.ActionDenied {
		t.Fatalf("second action = %q, want denied after the flagged amount was recorded", second.ActionTaken)
	}
}

func TestProxy_AuditFailureFailsClosedForEveryProceedingNonAllowAction(t *testing.T) {
	tests := []struct {
		name   string
		policy domain.Policy
	}{
		{"shadow", operationalPolicy("shadow-deny", domain.PolicyModeShadow, domain.EffectDeny, "amount", 0)},
		{"flagged", operationalPolicy("flag", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newOperationalTestProxy(t, []domain.Policy{tt.policy}, false)
			if err := p.auditLog.Close(); err != nil {
				t.Fatal(err)
			}

			_, result := evaluateOperational(t, p, "audit-failure-"+tt.name, 100)
			if result.ActionTaken != domain.ActionDenied {
				t.Fatalf("audit failure action = %q, want denied", result.ActionTaken)
			}
			assertOperationalDenyHasNoPolicyAttribution(t, result)
			if p.auditFailureCount.Load() != 1 || p.denyCount.Load() != 1 {
				t.Errorf("audit failure counters: audit=%d deny=%d, want 1/1", p.auditFailureCount.Load(), p.denyCount.Load())
			}
		})
	}
}

func TestProxy_AuditRollbackFailurePoisonsReadinessAndSkipsRetry(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("proceeding-flag", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0),
	}, false)
	fault := &faultInjectAuditFile{
		auditLogFile:         p.auditLog,
		shortWritesRemaining: 1,
		failTruncate:         true,
	}
	p.auditLog = fault

	_, result := evaluateOperational(t, p, "poisoned-audit", 100)
	if result.ActionTaken != domain.ActionDenied {
		t.Fatalf("action after poisoned audit append = %q, want denied", result.ActionTaken)
	}
	assertOperationalDenyHasNoPolicyAttribution(t, result)
	if fault.writeCalls != 1 {
		t.Fatalf("audit writes = %d, want exactly 1 (no poisoned-writer retry)", fault.writeCalls)
	}
	if !p.auditPoisoned || p.auditPoisonReason == "" {
		t.Fatalf("audit poison state = %v/%q, want sticky reason", p.auditPoisoned, p.auditPoisonReason)
	}

	writeCalls := fault.writeCalls
	err := p.appendTrace(&domain.DecisionTrace{TraceID: "must-not-write"})
	if !errors.Is(err, errAuditWriterPoisoned) {
		t.Fatalf("append after poison = %v, want errAuditWriterPoisoned", err)
	}
	if fault.writeCalls != writeCalls {
		t.Fatalf("poisoned append reached file: writes=%d, want %d", fault.writeCalls, writeCalls)
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	p.readyz(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "audit writer is poisoned") {
		t.Fatalf("readyz body does not explain poisoned audit writer: %s", rec.Body.String())
	}
}

func TestProxy_FullWriteSyncFailureRollsBackAndFailsClosed(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("proceeding-flag", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0),
	}, false)
	p.auditSyncMode = "every"
	fault := &faultInjectAuditFile{
		auditLogFile:          p.auditLog,
		syncFailuresRemaining: 1,
	}
	p.auditLog = fault

	_, result := evaluateOperational(t, p, "sync-uncertain", 100)
	if result.ActionTaken != domain.ActionDenied {
		t.Fatalf("action after full write and failed sync = %q, want fail-closed deny", result.ActionTaken)
	}
	assertOperationalDenyHasNoPolicyAttribution(t, result)
	if fault.writeCalls != 2 {
		t.Fatalf("audit writes = %d, want rolled-back original plus one durable deny", fault.writeCalls)
	}
	if p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf("audit state: poisoned=%v failures=%d, want false/1 after proven rollback", p.auditPoisoned, p.auditFailureCount.Load())
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].ActionTaken != result.ActionTaken || traces[0].Decision != result.Decision {
		t.Fatalf("audit traces = %#v, want one durable deny matching response %#v", traces, result)
	}

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	readyRec := httptest.NewRecorder()
	p.readyz(readyRec, readyReq)
	if readyRec.Code != http.StatusOK {
		t.Fatalf("readyz status = %d, want 200 after proven rollback and durable deny; body=%s", readyRec.Code, readyRec.Body.String())
	}
}

func TestProxy_FullWriteRollbackFailurePoisonsAndFailsClosedWithoutRetry(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("proceeding-flag", domain.PolicyModeEnforcement, domain.EffectFlag, "amount", 0),
	}, false)
	p.auditSyncMode = "every"
	fault := &faultInjectAuditFile{
		auditLogFile:          p.auditLog,
		syncFailuresRemaining: 1,
		failTruncate:          true,
	}
	p.auditLog = fault

	_, result := evaluateOperational(t, p, "sync-rollback-uncertain", 100)
	if result.ActionTaken != domain.ActionDenied {
		t.Fatalf("action after uncertain full write = %q, want fail-closed deny", result.ActionTaken)
	}
	assertOperationalDenyHasNoPolicyAttribution(t, result)
	if fault.writeCalls != 1 {
		t.Fatalf("audit writes = %d, want one write and no retry against poisoned tail", fault.writeCalls)
	}
	if !p.auditPoisoned || p.auditFailureCount.Load() != 1 {
		t.Fatalf("audit state: poisoned=%v failures=%d, want true/1", p.auditPoisoned, p.auditFailureCount.Load())
	}
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 || traces[0].ActionTaken != domain.ActionFlagged {
		t.Fatalf("uncertain on-disk trace = %#v, want the one possibly-written pre-deny trace", traces)
	}

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	readyRec := httptest.NewRecorder()
	p.readyz(readyRec, readyReq)
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want 503 after unprovable rollback; body=%s", readyRec.Code, readyRec.Body.String())
	}
}

func TestProxy_EscalationRegistrationFailureClearsPolicyAttribution(t *testing.T) {
	tests := []struct {
		name     string
		firstID  string
		secondID string
		storeCap int
	}{
		{name: "envelope collision", firstID: "duplicate", secondID: "duplicate"},
		{name: "pending store cap", firstID: "first", secondID: "second", storeCap: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newOperationalTestProxy(t, []domain.Policy{
				operationalPolicy("enforced-escalate", domain.PolicyModeEnforcement, domain.EffectEscalate, "amount", 0),
			}, false)
			if tt.storeCap > 0 {
				p.escalations.maxEntries = tt.storeCap
			}

			firstStatus, first := evaluateOperational(t, p, tt.firstID, 100)
			if firstStatus != http.StatusAccepted || first.ActionTaken != domain.ActionEscalated {
				t.Fatalf("first status/action = %d/%q, want 202/escalated", firstStatus, first.ActionTaken)
			}
			secondStatus, second := evaluateOperational(t, p, tt.secondID, 100)
			if secondStatus != http.StatusOK || second.ActionTaken != domain.ActionDenied {
				t.Fatalf("second status/action = %d/%q, want 200/denied", secondStatus, second.ActionTaken)
			}
			assertOperationalDenyHasNoPolicyAttribution(t, second)

			traces := readOperationalTraces(t, p)
			if len(traces) != 2 {
				t.Fatalf("audit trace count = %d, want 2", len(traces))
			}
			last := traces[1]
			if last.CanonicalVersion != "v2" {
				t.Errorf("canonical version = %q, want v2", last.CanonicalVersion)
			}
			if last.ActionTaken != domain.ActionDenied {
				t.Errorf("audit action = %q, want denied", last.ActionTaken)
			}
			if last.Amount != 100 || last.AmountParseStatus != engine.AmountParseOK {
				t.Errorf("audit amount provenance = (%v, %q), want (100, %q)", last.Amount, last.AmountParseStatus, engine.AmountParseOK)
			}
			if len(last.AppliedRuleResults) != 0 || last.AppliedPrimaryCitation != nil {
				t.Errorf("audit operational deny retained applied provenance: rules=%#v citation=%#v",
					last.AppliedRuleResults, last.AppliedPrimaryCitation)
			}
			if last.PrimaryCitation != nil || last.SuggestedResponse != "" {
				t.Errorf("audit operational deny retained policy attribution: citation=%#v guidance=%q",
					last.PrimaryCitation, last.SuggestedResponse)
			}
		})
	}
}

func TestProxy_UnknownToolOperationalDenyClearsShadowPolicyAttribution(t *testing.T) {
	// The tool is declared, but only by a shadow policy. The enforcement-only
	// unknown-tool boundary must deny it and explain that distinction.
	policy := operationalPolicy("shadow-only", domain.PolicyModeShadow, domain.EffectDeny, "amount", 0)
	p := newOperationalTestProxy(t, []domain.Policy{policy}, false)
	p.unknownToolsDeny = true

	status, result := evaluateOperationalTool(t, p, "unknown-tool", "issue_refund", "monetary_outflow", 100)
	if status != http.StatusOK || result.ActionTaken != domain.ActionDenied {
		t.Fatalf("status/action = %d/%q, want 200/denied", status, result.ActionTaken)
	}
	assertOperationalDenyHasNoPolicyAttribution(t, result)
	traces := readOperationalTraces(t, p)
	if len(traces) != 1 {
		t.Fatalf("audit trace count = %d, want 1", len(traces))
	}
	if len(traces[0].AppliedRuleResults) != 0 || traces[0].AppliedPrimaryCitation != nil {
		t.Fatalf("unknown-tool audit retained applied provenance: %#v", traces[0])
	}
	if traces[0].PrimaryCitation != nil || traces[0].SuggestedResponse != "" {
		t.Fatalf("unknown-tool audit retained policy attribution: %#v", traces[0])
	}
	if !strings.Contains(result.DecisionReason, "loaded enforcement policy") {
		t.Fatalf("unknown-tool reason does not explain enforcement-only lookup: %q", result.DecisionReason)
	}
}

func TestProxy_ShadowTimeoutCannotControlEnforcedEscalation(t *testing.T) {
	shadow := operationalPolicy("shadow-escalate", domain.PolicyModeShadow, domain.EffectEscalate, "amount", 0)
	shadow.Priority = 1
	shadow.Rules[0].EffectConfig.TimeoutMinutes = 1
	shadow.Rules[0].Citation.Excerpt = "shadow telemetry"
	enforced := operationalPolicy("enforced-escalate", domain.PolicyModeEnforcement, domain.EffectEscalate, "amount", 0)
	enforced.Priority = 2
	enforced.Rules[0].EffectConfig.TimeoutMinutes = 9
	enforced.Rules[0].Citation.Excerpt = "enforcement approval"

	p := newOperationalTestProxy(t, []domain.Policy{shadow, enforced}, false)
	status, result := evaluateOperational(t, p, "mixed-timeout", 100)
	if status != http.StatusAccepted || result.ActionTaken != domain.ActionEscalated {
		t.Fatalf("status/action = %d/%q, want 202/escalated", status, result.ActionTaken)
	}
	pending := p.escalations.get("mixed-timeout")
	if pending == nil {
		t.Fatal("enforced escalation was not registered")
	}
	if got := pending.ExpiresAt.Sub(pending.CreatedAt).Round(time.Minute); got != 9*time.Minute {
		t.Fatalf("pending timeout = %s, want enforcement policy's 9m", got)
	}
	if result.PrimaryCitation == nil || result.PrimaryCitation.Excerpt != "shadow telemetry" {
		t.Fatalf("aggregate primary citation = %#v, want shadow telemetry", result.PrimaryCitation)
	}
	if result.AppliedPrimaryCitation == nil || result.AppliedPrimaryCitation.Excerpt != "enforcement approval" {
		t.Fatalf("applied primary citation = %#v, want enforcement approval", result.AppliedPrimaryCitation)
	}
	if len(result.AppliedRuleResults) != 1 || result.AppliedRuleResults[0].PolicyID != "enforced-escalate" {
		t.Fatalf("applied rule results = %#v, want only enforced-escalate", result.AppliedRuleResults)
	}
}
