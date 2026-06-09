package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestEvalCondition_LeafOperators(t *testing.T) {
	fields := map[string]interface{}{
		"amount":        float64(500),
		"amount_str":    "500.00",
		"tool_name":     "issue_refund",
		"customer_tier": "gold",
		"order_age":     float64(30),
		"email":         "test@example.com",
		"count":         float64(5),
	}

	tests := []struct {
		name   string
		cond   domain.Condition
		expect bool
	}{
		{
			name:   "eq match",
			cond:   domain.Condition{Field: "tool_name", Operator: domain.OpEq, Value: "issue_refund"},
			expect: true,
		},
		{
			name:   "eq match numeric string coerced",
			cond:   domain.Condition{Field: "amount_str", Operator: domain.OpEq, Value: float64(500)},
			expect: true,
		},
		{
			name:   "neq match numeric string coerced",
			cond:   domain.Condition{Field: "amount_str", Operator: domain.OpNeq, Value: float64(400)},
			expect: true,
		},
		{
			name:   "gt match numeric string coerced",
			cond:   domain.Condition{Field: "amount_str", Operator: domain.OpGt, Value: float64(400)},
			expect: true,
		},
		{
			name:   "lt match numeric string coerced",
			cond:   domain.Condition{Field: "amount_str", Operator: domain.OpLt, Value: float64(600)},
			expect: true,
		},
		{
			name:   "eq no match",
			cond:   domain.Condition{Field: "tool_name", Operator: domain.OpEq, Value: "other_tool"},
			expect: false,
		},
		{
			name:   "neq match",
			cond:   domain.Condition{Field: "tool_name", Operator: domain.OpNeq, Value: "other_tool"},
			expect: true,
		},
		{
			name:   "neq no match",
			cond:   domain.Condition{Field: "tool_name", Operator: domain.OpNeq, Value: "issue_refund"},
			expect: false,
		},
		{
			name:   "gt match",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(400)},
			expect: true,
		},
		{
			name:   "gt no match",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
			expect: false,
		},
		{
			name:   "gte match equal",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGte, Value: float64(500)},
			expect: true,
		},
		{
			name:   "gte match greater",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGte, Value: float64(400)},
			expect: true,
		},
		{
			name:   "lt match",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpLt, Value: float64(600)},
			expect: true,
		},
		{
			name:   "lt no match",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpLt, Value: float64(500)},
			expect: false,
		},
		{
			name:   "lte match equal",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpLte, Value: float64(500)},
			expect: true,
		},
		{
			name:   "in match",
			cond:   domain.Condition{Field: "customer_tier", Operator: domain.OpIn, Value: []interface{}{"gold", "platinum"}},
			expect: true,
		},
		{
			name:   "in no match",
			cond:   domain.Condition{Field: "customer_tier", Operator: domain.OpIn, Value: []interface{}{"silver", "bronze"}},
			expect: false,
		},
		{
			name:   "contains match",
			cond:   domain.Condition{Field: "email", Operator: domain.OpContains, Value: "example.com"},
			expect: true,
		},
		{
			name:   "contains no match",
			cond:   domain.Condition{Field: "email", Operator: domain.OpContains, Value: "other.com"},
			expect: false,
		},
		{
			name:   "regex match",
			cond:   domain.Condition{Field: "email", Operator: domain.OpRegex, Value: `^test@.*\.com$`},
			expect: true,
		},
		{
			name:   "regex no match",
			cond:   domain.Condition{Field: "email", Operator: domain.OpRegex, Value: `^admin@.*\.com$`},
			expect: false,
		},
		{
			name:   "missing field returns false",
			cond:   domain.Condition{Field: "nonexistent", Operator: domain.OpEq, Value: "anything"},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvalCondition(tt.cond, fields)
			if result != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestEvalCondition_FieldComparison(t *testing.T) {
	fields := map[string]interface{}{
		"amount":      float64(500),
		"order_total": float64(300),
		"limit":       float64(1000),
	}

	tests := []struct {
		name   string
		cond   domain.Condition
		expect bool
	}{
		{
			name:   "gt_field match (amount > order_total)",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGtField, Value: "order_total"},
			expect: true,
		},
		{
			name:   "gt_field no match (amount > limit)",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpGtField, Value: "limit"},
			expect: false,
		},
		{
			name:   "lt_field match (amount < limit)",
			cond:   domain.Condition{Field: "amount", Operator: domain.OpLtField, Value: "limit"},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvalCondition(tt.cond, fields)
			if result != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestEvalCondition_LogicalOperators(t *testing.T) {
	fields := map[string]interface{}{
		"amount":        float64(500),
		"customer_tier": "gold",
		"order_age":     float64(30),
	}

	tests := []struct {
		name   string
		cond   domain.Condition
		expect bool
	}{
		{
			name: "AND all true",
			cond: domain.Condition{
				And: []domain.Condition{
					{Field: "amount", Operator: domain.OpGt, Value: float64(100)},
					{Field: "customer_tier", Operator: domain.OpEq, Value: "gold"},
				},
			},
			expect: true,
		},
		{
			name: "AND one false",
			cond: domain.Condition{
				And: []domain.Condition{
					{Field: "amount", Operator: domain.OpGt, Value: float64(100)},
					{Field: "customer_tier", Operator: domain.OpEq, Value: "silver"},
				},
			},
			expect: false,
		},
		{
			name: "OR one true",
			cond: domain.Condition{
				Or: []domain.Condition{
					{Field: "customer_tier", Operator: domain.OpEq, Value: "silver"},
					{Field: "customer_tier", Operator: domain.OpEq, Value: "gold"},
				},
			},
			expect: true,
		},
		{
			name: "OR all false",
			cond: domain.Condition{
				Or: []domain.Condition{
					{Field: "customer_tier", Operator: domain.OpEq, Value: "silver"},
					{Field: "customer_tier", Operator: domain.OpEq, Value: "bronze"},
				},
			},
			expect: false,
		},
		{
			name: "NOT true becomes false",
			cond: domain.Condition{
				Not: &domain.Condition{Field: "customer_tier", Operator: domain.OpEq, Value: "gold"},
			},
			expect: false,
		},
		{
			name: "NOT false becomes true",
			cond: domain.Condition{
				Not: &domain.Condition{Field: "customer_tier", Operator: domain.OpEq, Value: "silver"},
			},
			expect: true,
		},
		{
			name: "nested AND(OR(a,b), NOT(c))",
			cond: domain.Condition{
				And: []domain.Condition{
					{
						Or: []domain.Condition{
							{Field: "amount", Operator: domain.OpGt, Value: float64(1000)},
							{Field: "customer_tier", Operator: domain.OpEq, Value: "gold"},
						},
					},
					{
						Not: &domain.Condition{
							Field: "order_age", Operator: domain.OpGt, Value: float64(90),
						},
					},
				},
			},
			expect: true, // OR: gold=gold -> true; NOT: 30>90 -> false -> NOT -> true; AND: true & true
		},
		{
			name:   "empty condition matches everything",
			cond:   domain.Condition{},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvalCondition(tt.cond, fields)
			if result != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestFlattenEnvelope_ContentFields(t *testing.T) {
	env := &domain.ActionEnvelope{
		EnvelopeID: "env-1",
		AgentID:    "agent-1",
		OrgID:      "org-1",
		ToolName:   "send_sms",
		ToolGroup:  "messaging",
	}
	env.Context.Verified.ContentRisk = "high"
	env.Context.Verified.ContentCategories = []string{"violence", "threats"}
	env.Context.Verified.ContentClassifierTier = "regex"

	fields := FlattenEnvelope(env)

	// Check content_risk
	if v, ok := fields["context.verified.content_risk"]; !ok || v != "high" {
		t.Errorf("content_risk: expected 'high', got %v", v)
	}

	// Check content_categories (comma-joined)
	if v, ok := fields["context.verified.content_categories"]; !ok || v != "violence,threats" {
		t.Errorf("content_categories: expected 'violence,threats', got %v", v)
	}

	// Check content_classifier_tier
	if v, ok := fields["context.verified.content_classifier_tier"]; !ok || v != "regex" {
		t.Errorf("content_classifier_tier: expected 'regex', got %v", v)
	}

	// Verify contains operator works on comma-joined categories
	cond := domain.Condition{
		Field:    "context.verified.content_categories",
		Operator: domain.OpContains,
		Value:    "violence",
	}
	if !EvalCondition(cond, fields) {
		t.Error("expected contains 'violence' to match")
	}

	notCond := domain.Condition{
		Field:    "context.verified.content_categories",
		Operator: domain.OpContains,
		Value:    "profanity",
	}
	if EvalCondition(notCond, fields) {
		t.Error("expected contains 'profanity' to NOT match")
	}
}

func TestFlattenEnvelope_ContentFieldsEmpty(t *testing.T) {
	env := &domain.ActionEnvelope{
		EnvelopeID: "env-2",
		AgentID:    "agent-1",
		OrgID:      "org-1",
		ToolName:   "issue_refund",
		ToolGroup:  "financial",
	}
	// No content fields set

	fields := FlattenEnvelope(env)

	if v := fields["context.verified.content_risk"]; v != "" {
		t.Errorf("expected empty content_risk, got %v", v)
	}
	if v := fields["context.verified.content_categories"]; v != "" {
		t.Errorf("expected empty content_categories, got %v", v)
	}
	if v := fields["context.verified.content_classifier_tier"]; v != "" {
		t.Errorf("expected empty content_classifier_tier, got %v", v)
	}
}

func TestResolveField_DotNotation(t *testing.T) {
	fields := map[string]interface{}{
		"context": map[string]interface{}{
			"verified": map[string]interface{}{
				"customer_tier": "gold",
				"order_total":   float64(100),
			},
		},
		"flat_key": "value",
	}

	tests := []struct {
		name   string
		path   string
		expect interface{}
		exists bool
	}{
		{"nested path", "context.verified.customer_tier", "gold", true},
		{"nested numeric", "context.verified.order_total", float64(100), true},
		{"flat key", "flat_key", "value", true},
		{"missing key", "context.verified.missing", nil, false},
		{"missing nested", "nonexistent.path", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, exists := resolveField(tt.path, fields)
			if exists != tt.exists {
				t.Errorf("exists: expected %v, got %v", tt.exists, exists)
			}
			if exists && val != tt.expect {
				t.Errorf("value: expected %v, got %v", tt.expect, val)
			}
		})
	}
}
