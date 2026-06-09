package engine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func makeEnvelope(amount float64, toolName, agentID, orgID string) *domain.ActionEnvelope {
	params, _ := json.Marshal(map[string]interface{}{"amount": amount})
	return &domain.ActionEnvelope{
		EnvelopeID: "env-001",
		Timestamp:  time.Now(),
		AgentID:    agentID,
		SessionID:  "sess-001",
		OrgID:      orgID,
		ToolName:   toolName,
		ToolGroup:  "monetary_outflow",
		Parameters: params,
		Context: domain.EnvelopeContext{
			Verified: domain.VerifiedContext{
				CustomerTier:    "gold",
				OrderTotal:      1000,
				OrderAge:        15,
				Rolling24hTotal: 300,
				Rolling24hCount: 2,
				AgentBudget: &domain.AgentBudgetContext{
					TotalLimit:        2000,
					UsedToday:         300,
					Remaining:         1700,
					TransactionsToday: 2,
				},
			},
			SessionState: domain.SessionStateContext{
				CumulativeAmount: 300,
				ActionsInSession: 2,
			},
		},
	}
}

func makePolicy(rules []domain.Rule) domain.Policy {
	return domain.Policy{
		PolicyID: "pol-001",
		OrgID:    "org-001",
		Name:     "test-policy",
		Version:  1,
		Status:   domain.PolicyStatusApproved,
		Mode:     domain.PolicyModeShadow,
		Scope: domain.PolicyScope{
			ToolNames: []string{"issue_refund"},
		},
		Rules:     rules,
		CreatedBy: "user-001",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestEvaluator_AllowedWhenNoRulesTriggered(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(200, "issue_refund", "agent-001", "org-001")

	policy := makePolicy([]domain.Rule{
		{
			RuleID: "rule-001",
			Name:   "high-amount",
			Conditions: domain.Condition{
				Field: "amount", Operator: domain.OpGt, Value: float64(500),
			},
			Effect: domain.EffectDeny,
			Citation: domain.Citation{
				DocumentID: "doc-001",
				Excerpt:    "Refunds over $500 require approval",
			},
		},
	})

	result := eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeShadow)

	if result.Decision != domain.DecisionAllowed {
		t.Errorf("expected allowed, got %s", result.Decision)
	}
	if result.ActionTaken != domain.ActionAllowed {
		t.Errorf("expected allowed action, got %s", result.ActionTaken)
	}
	if result.RulesEvaluated != 1 {
		t.Errorf("expected 1 rule evaluated, got %d", result.RulesEvaluated)
	}
	if result.RulesTriggered != 0 {
		t.Errorf("expected 0 rules triggered, got %d", result.RulesTriggered)
	}
	if result.IsNearMiss {
		t.Error("should not be near miss")
	}
}

func TestEvaluator_DeniedInShadowIsNearMiss(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	policy := makePolicy([]domain.Rule{
		{
			RuleID: "rule-001",
			Name:   "high-amount",
			Conditions: domain.Condition{
				Field: "amount", Operator: domain.OpGt, Value: float64(500),
			},
			Effect:       domain.EffectDeny,
			EffectConfig: domain.EffectConfig{Severity: "high", SuggestedResponse: "Refund exceeds limit"},
			Citation: domain.Citation{
				DocumentID: "doc-001",
				Section:    "2.3",
				Excerpt:    "Refunds over $500 require manager approval",
			},
		},
	})

	result := eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeShadow)

	if result.Decision != domain.DecisionDenied {
		t.Errorf("expected denied, got %s", result.Decision)
	}
	if result.ActionTaken != domain.ActionAllowedShadow {
		t.Errorf("expected allowed_shadow, got %s", result.ActionTaken)
	}
	if !result.IsNearMiss {
		t.Error("expected near miss in shadow mode")
	}
	if result.PrimaryCitation == nil {
		t.Error("expected primary citation")
	}
	if result.SuggestedResponse != "Refund exceeds limit" {
		t.Errorf("expected suggested response, got %q", result.SuggestedResponse)
	}
}

func TestEvaluator_DeniedInEnforcementMode(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	policy := makePolicy([]domain.Rule{
		{
			RuleID: "rule-001",
			Name:   "high-amount",
			Conditions: domain.Condition{
				Field: "amount", Operator: domain.OpGt, Value: float64(500),
			},
			Effect: domain.EffectDeny,
			Citation: domain.Citation{
				DocumentID: "doc-001",
				Excerpt:    "Refunds over $500 denied",
			},
		},
	})

	result := eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)

	if result.Decision != domain.DecisionDenied {
		t.Errorf("expected denied, got %s", result.Decision)
	}
	if result.ActionTaken != domain.ActionDenied {
		t.Errorf("expected denied action, got %s", result.ActionTaken)
	}
	if result.IsNearMiss {
		t.Error("should not be near miss in enforcement mode")
	}
}

func TestEvaluator_EffectHierarchy(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	policy := makePolicy([]domain.Rule{
		{
			RuleID:     "rule-flag",
			Name:       "flag-large",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(200)},
			Effect:     domain.EffectFlag,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Flag large refunds"},
		},
		{
			RuleID:     "rule-escalate",
			Name:       "escalate-high",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(400)},
			Effect:     domain.EffectEscalate,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Escalate high refunds"},
		},
		{
			RuleID:     "rule-deny",
			Name:       "deny-very-high",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(700)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Deny very high refunds"},
		},
	})

	result := eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)

	// Deny > escalate > flag, so deny wins
	if result.Decision != domain.DecisionDenied {
		t.Errorf("expected denied (highest severity), got %s", result.Decision)
	}
	if result.RulesTriggered != 3 {
		t.Errorf("expected 3 rules triggered, got %d", result.RulesTriggered)
	}
}

func TestEvaluator_EmptyPolicySetAllows(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(10000, "issue_refund", "agent-001", "org-001")

	result := eval.Evaluate(env, []domain.Policy{}, domain.PolicyModeEnforcement)

	if result.Decision != domain.DecisionAllowed {
		t.Errorf("expected allowed with no policies, got %s", result.Decision)
	}
	if result.PoliciesMatched != 0 {
		t.Errorf("expected 0 policies matched, got %d", result.PoliciesMatched)
	}
}

func TestEvaluator_PolicyScopeFiltering(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	// Policy scoped to different tool
	otherPolicy := makePolicy([]domain.Rule{
		{
			RuleID:     "rule-deny",
			Name:       "deny-all",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(0)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Deny"},
		},
	})
	otherPolicy.Scope.ToolNames = []string{"other_tool"}

	result := eval.Evaluate(env, []domain.Policy{otherPolicy}, domain.PolicyModeEnforcement)

	if result.Decision != domain.DecisionAllowed {
		t.Errorf("expected allowed (policy scope doesn't match), got %s", result.Decision)
	}
	if result.PoliciesMatched != 0 {
		t.Errorf("expected 0 matched policies, got %d", result.PoliciesMatched)
	}
}

func TestEvaluator_OnlyApprovedPoliciesEvaluated(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	draftPolicy := makePolicy([]domain.Rule{
		{
			RuleID:     "rule-deny",
			Name:       "deny-all",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(0)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Deny"},
		},
	})
	draftPolicy.Status = domain.PolicyStatusDraft

	result := eval.Evaluate(env, []domain.Policy{draftPolicy}, domain.PolicyModeEnforcement)

	if result.Decision != domain.DecisionAllowed {
		t.Errorf("expected allowed (draft policy skipped), got %s", result.Decision)
	}
}

func TestEvaluator_MultiplePolicies(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(800, "issue_refund", "agent-001", "org-001")

	flagPolicy := makePolicy([]domain.Rule{
		{
			RuleID:     "rule-flag",
			Name:       "flag-high",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(300)},
			Effect:     domain.EffectFlag,
			Citation:   domain.Citation{DocumentID: "doc-001", Excerpt: "Flag"},
		},
	})
	flagPolicy.PolicyID = "pol-flag"

	denyPolicy := makePolicy([]domain.Rule{
		{
			RuleID:     "rule-deny",
			Name:       "deny-age",
			Conditions: domain.Condition{Field: "context.verified.order_age_days", Operator: domain.OpGt, Value: float64(90)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{DocumentID: "doc-002", Excerpt: "Deny old orders"},
		},
	})
	denyPolicy.PolicyID = "pol-deny"

	result := eval.Evaluate(env, []domain.Policy{flagPolicy, denyPolicy}, domain.PolicyModeEnforcement)

	// order_age=15 < 90, so deny rule doesn't trigger; flag rule triggers
	if result.Decision != domain.DecisionFlagged {
		t.Errorf("expected flagged, got %s", result.Decision)
	}
	if result.PoliciesMatched != 2 {
		t.Errorf("expected 2 policies matched, got %d", result.PoliciesMatched)
	}
}

func TestEvaluator_SessionCumulativeCheck(t *testing.T) {
	eval := NewEvaluator()
	env := makeEnvelope(200, "issue_refund", "agent-001", "org-001")
	env.Context.SessionState.CumulativeAmount = 900

	policy := makePolicy([]domain.Rule{
		{
			RuleID: "rule-cumulative",
			Name:   "session-limit",
			Conditions: domain.Condition{
				Field: "context.session_state.cumulative_amount", Operator: domain.OpGt, Value: float64(800),
			},
			Effect: domain.EffectEscalate,
			Citation: domain.Citation{
				DocumentID: "doc-001",
				Excerpt:    "Session cumulative exceeds $800",
			},
		},
	})

	result := eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)

	if result.Decision != domain.DecisionEscalated {
		t.Errorf("expected escalated, got %s", result.Decision)
	}
}
