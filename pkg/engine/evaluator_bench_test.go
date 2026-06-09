package engine

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func benchEnvelope() *domain.ActionEnvelope {
	params, _ := json.Marshal(map[string]interface{}{"amount": 450.0})
	return &domain.ActionEnvelope{
		EnvelopeID: "env-bench-001",
		Timestamp:  time.Now(),
		AgentID:    "agent-bench",
		SessionID:  "sess-bench",
		OrgID:      "org-bench",
		ToolName:   "issue_refund",
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

func benchPolicy(rules []domain.Rule) domain.Policy {
	return domain.Policy{
		PolicyID:  "pol-bench",
		OrgID:     "org-bench",
		Name:      "bench-policy",
		Version:   1,
		Status:    domain.PolicyStatusApproved,
		Mode:      domain.PolicyModeEnforcement,
		Scope:     domain.PolicyScope{ToolNames: []string{"issue_refund"}},
		Rules:     rules,
		CreatedBy: "user-bench",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func BenchmarkEvaluate_SingleRule(b *testing.B) {
	eval := NewEvaluator()
	env := benchEnvelope()
	policies := []domain.Policy{benchPolicy([]domain.Rule{
		{
			RuleID:     "r1",
			Name:       "cap",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{Excerpt: "Cap"},
		},
	})}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(env, policies, domain.PolicyModeEnforcement)
	}
}

func BenchmarkEvaluate_TenRules(b *testing.B) {
	eval := NewEvaluator()
	env := benchEnvelope()

	var rules []domain.Rule
	for i := 0; i < 10; i++ {
		rules = append(rules, domain.Rule{
			RuleID:     fmt.Sprintf("r%d", i),
			Name:       fmt.Sprintf("rule-%d", i),
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(100 + i*50)},
			Effect:     domain.EffectFlag,
			Citation:   domain.Citation{Excerpt: "Rule"},
		})
	}
	policies := []domain.Policy{benchPolicy(rules)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(env, policies, domain.PolicyModeEnforcement)
	}
}

func BenchmarkEvaluate_ComplexConditions(b *testing.B) {
	eval := NewEvaluator()
	env := benchEnvelope()

	policies := []domain.Policy{benchPolicy([]domain.Rule{
		{
			RuleID: "complex",
			Name:   "complex-rule",
			Conditions: domain.Condition{
				And: []domain.Condition{
					{Field: "amount", Operator: domain.OpGt, Value: float64(100)},
					{Field: "context.verified.customer_tier", Operator: domain.OpEq, Value: "gold"},
					{
						Or: []domain.Condition{
							{Field: "context.verified.rolling_24h_total", Operator: domain.OpGt, Value: float64(1000)},
							{Field: "context.session_state.cumulative_amount", Operator: domain.OpGt, Value: float64(500)},
						},
					},
				},
			},
			Effect:   domain.EffectEscalate,
			Citation: domain.Citation{Excerpt: "Complex rule"},
		},
	})}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(env, policies, domain.PolicyModeEnforcement)
	}
}
