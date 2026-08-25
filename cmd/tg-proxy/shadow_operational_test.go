package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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
			Citation:   domain.Citation{DocumentID: "test", Excerpt: "operational shadow regression"},
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
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"envelope_id": envelopeID,
		"agent_id":    "shadow-agent",
		"session_id":  "shadow-session",
		"org_id":      "shadow-org",
		"tool_name":   "issue_refund",
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
			if p.auditFailureCount.Load() != 1 || p.denyCount.Load() != 1 {
				t.Errorf("audit failure counters: audit=%d deny=%d, want 1/1", p.auditFailureCount.Load(), p.denyCount.Load())
			}
		})
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
