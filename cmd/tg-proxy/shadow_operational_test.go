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

func TestProxy_AuditFailureFailsClosedForShadowProceedingAction(t *testing.T) {
	p := newOperationalTestProxy(t, []domain.Policy{
		operationalPolicy("shadow-deny", domain.PolicyModeShadow, domain.EffectDeny, "amount", 0),
	}, false)
	if err := p.auditLog.Close(); err != nil {
		t.Fatal(err)
	}

	_, result := evaluateOperational(t, p, "audit-failure", 100)
	if result.ActionTaken != domain.ActionDenied {
		t.Fatalf("audit failure action = %q, want denied", result.ActionTaken)
	}
	if p.auditFailureCount.Load() != 1 || p.denyCount.Load() != 1 {
		t.Errorf("audit failure counters: audit=%d deny=%d, want 1/1", p.auditFailureCount.Load(), p.denyCount.Load())
	}
}
