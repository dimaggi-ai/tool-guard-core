package engine_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// An empty condition node returns true from EvalCondition and would
// match every call. ValidatePolicy refuses to load such a policy.
func TestValidatePolicy_RejectsEmptyCondition(t *testing.T) {
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{
			{
				RuleID:     "match-all",
				Conditions: domain.Condition{}, // intentionally empty
				Effect:     domain.EffectDeny,
			},
		},
	}
	err := engine.ValidatePolicy(p)
	if err == nil {
		t.Fatalf("expected error for empty condition; got nil")
	}
	if !strings.Contains(err.Error(), "empty condition") {
		t.Errorf("error message doesn't name empty condition: %v", err)
	}
}

// A regex that doesn't compile causes compareRegex to return false at
// runtime, so the rule silently never fires. ValidatePolicy refuses
// such a policy at load.
func TestValidatePolicy_RejectsBadRegex(t *testing.T) {
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{
			{
				RuleID: "deny-bad-regex",
				Conditions: domain.Condition{
					Field:    "parameters.sql",
					Operator: domain.OpRegex,
					Value:    "(?i)\\b(DROP|TRUNCATE", // missing close paren
				},
				Effect: domain.EffectDeny,
			},
		},
	}
	err := engine.ValidatePolicy(p)
	if err == nil {
		t.Fatalf("expected error for bad regex; got nil")
	}
	if !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("error message doesn't name regex compile failure: %v", err)
	}
}

// A classifier leaf is fail-CLOSED: it fires on malformed/adversarial
// input so a deny rule trips. Negating it with not: inverts that into
// fail-OPEN — the malformed input is then allowed through. ValidatePolicy
// refuses any classifier under a not: node.
func TestValidatePolicy_RejectsClassifierUnderNot(t *testing.T) {
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{
			{
				RuleID: "deny-unless-clean-select",
				Conditions: domain.Condition{
					Not: &domain.Condition{
						SQLClassify: &domain.SQLClassify{
							Field:   "parameters.query",
							Dialect: "postgres",
							Require: domain.SQLRequire{TopLevelKinds: []string{"SELECT"}},
						},
					},
				},
				Effect: domain.EffectDeny,
			},
		},
	}
	err := engine.ValidatePolicy(p)
	if err == nil {
		t.Fatalf("expected rejection of a classifier under not: (fail-open inversion); got nil")
	}
	if !strings.Contains(err.Error(), "not:") {
		t.Errorf("error doesn't explain the not: restriction: %v", err)
	}
}

// Bad regex in shell_classify deny-patterns
func TestValidatePolicy_RejectsBadShellDenyPattern(t *testing.T) {
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{
			{
				RuleID: "deny-bad-shell-regex",
				Conditions: domain.Condition{
					ShellClassify: &domain.ShellClassify{
						Field: "parameters.argv",
						Require: domain.ShellRequire{
							Argv0Allowlist:   []string{"ls"},
							ArgvDenyPatterns: []string{"[invalid"}, // unclosed character class
						},
					},
				},
				Effect: domain.EffectDeny,
			},
		},
	}
	err := engine.ValidatePolicy(p)
	if err == nil {
		t.Fatalf("expected error for bad shell deny pattern; got nil")
	}
}

// Mixed populated forms (And + Or, And + leaf, etc.)
func TestValidatePolicy_RejectsMixedConditionForms(t *testing.T) {
	cases := []struct {
		name string
		cond domain.Condition
	}{
		{
			name: "and + leaf",
			cond: domain.Condition{
				And:      []domain.Condition{{Field: "x", Operator: domain.OpEq, Value: "1"}},
				Field:    "y", // also a leaf — ambiguous
				Operator: domain.OpEq,
				Value:    "2",
			},
		},
		{
			name: "and + or",
			cond: domain.Condition{
				And: []domain.Condition{{Field: "x", Operator: domain.OpEq, Value: "1"}},
				Or:  []domain.Condition{{Field: "y", Operator: domain.OpEq, Value: "2"}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &domain.Policy{
				PolicyID: "test",
				Rules:    []domain.Rule{{RuleID: "r", Conditions: c.cond, Effect: domain.EffectDeny}},
			}
			err := engine.ValidatePolicy(p)
			if err == nil {
				t.Fatalf("expected error for mixed forms")
			}
			if !strings.Contains(err.Error(), "multiple populated") {
				t.Errorf("error doesn't name mixed forms: %v", err)
			}
		})
	}
}

// Clean policies pass.
func TestValidatePolicy_AcceptsCleanPolicies(t *testing.T) {
	cases := []domain.Condition{
		{Field: "tool_name", Operator: domain.OpEq, Value: "query"},
		{
			And: []domain.Condition{
				{Field: "tool_name", Operator: domain.OpEq, Value: "query"},
				{SQLClassify: &domain.SQLClassify{
					Field:   "parameters.sql",
					Dialect: "postgres",
					Require: domain.SQLRequire{TopLevelKinds: []string{"SELECT"}},
				}},
			},
		},
		{
			Not: &domain.Condition{
				Field:    "parameters.cmd",
				Operator: domain.OpRegex,
				Value:    "^(uptime|date|whoami)$",
			},
		},
		{
			PathClassify: &domain.PathClassify{
				Field: "parameters.path",
				Require: domain.PathRequire{
					CleanFirst:              true,
					DeniedCanonicalPrefixes: []string{"/etc/shadow"},
				},
			},
		},
	}
	for i, c := range cases {
		p := &domain.Policy{
			PolicyID: "test",
			Rules:    []domain.Rule{{RuleID: "r", Conditions: c, Effect: domain.EffectDeny}},
		}
		if err := engine.ValidatePolicy(p); err != nil {
			t.Errorf("case %d should be valid: %v", i, err)
		}
	}
}

// An operator/value type mismatch (e.g. `gt` with a non-numeric
// string) silently allows at runtime — the leaf returns false on
// every envelope so the rule never fires. ValidatePolicy refuses
// such a policy at load.
func TestValidatePolicy_TypeMismatch(t *testing.T) {
	cases := []struct {
		name string
		cond domain.Condition
		ok   bool
	}{
		{"gt on string value (was silent allow)", domain.Condition{Field: "amount", Operator: domain.OpGt, Value: "not a number"}, false},
		{"gt on number", domain.Condition{Field: "amount", Operator: domain.OpGt, Value: 500.0}, true},
		{"gt on int", domain.Condition{Field: "amount", Operator: domain.OpGt, Value: 500}, true},
		{"regex on number value", domain.Condition{Field: "x", Operator: domain.OpRegex, Value: 42}, false},
		{"regex on string", domain.Condition{Field: "x", Operator: domain.OpRegex, Value: "^foo$"}, true},
		{"in on scalar", domain.Condition{Field: "x", Operator: domain.OpIn, Value: "single"}, false},
		{"in on list", domain.Condition{Field: "x", Operator: domain.OpIn, Value: []interface{}{"a", "b"}}, true},
		{"gt_field with non-string", domain.Condition{Field: "x", Operator: domain.OpGtField, Value: 42}, false},
		{"gt_field with string", domain.Condition{Field: "x", Operator: domain.OpGtField, Value: "y"}, true},
		{"contains on non-string", domain.Condition{Field: "x", Operator: domain.OpContains, Value: 1}, false},
		{"contains on string", domain.Condition{Field: "x", Operator: domain.OpContains, Value: "needle"}, true},
		{"eq accepts anything", domain.Condition{Field: "x", Operator: domain.OpEq, Value: 1}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &domain.Policy{
				PolicyID: "test",
				Rules:    []domain.Rule{{RuleID: "r", Conditions: c.cond, Effect: domain.EffectDeny}},
			}
			err := engine.ValidatePolicy(p)
			if c.ok && err != nil {
				t.Errorf("expected ok, got error: %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// Validate populates the regex cache for every regex pattern it
// touches. Prewarm + repeated eval should reuse the cached compiled
// pattern (verified indirectly: 1000 evals must still pass).
func TestRegexCachePopulatedAndReused(t *testing.T) {
	pattern := `(?i)\bUNIQUE_PATTERN_FOR_CACHE_TEST_\d+\b`
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{{
			RuleID: "r",
			Conditions: domain.Condition{
				Field: "x", Operator: domain.OpRegex, Value: pattern,
			},
			Effect: domain.EffectDeny,
		}},
	}
	before := engine.CachedRegexCount()
	if err := engine.ValidatePolicy(p); err != nil {
		t.Fatalf("validate: %v", err)
	}
	after := engine.CachedRegexCount()
	if after < before+1 {
		t.Fatalf("ValidatePolicy did not populate cache (before=%d after=%d)", before, after)
	}

	// Repeated eval still works.
	fields := map[string]interface{}{"x": "UNIQUE_PATTERN_FOR_CACHE_TEST_42"}
	for i := 0; i < 1000; i++ {
		if !engine.EvalCondition(p.Rules[0].Conditions, fields) {
			t.Fatalf("regex rule did not fire on iter %d", i)
		}
	}
}

// Recursion budget: 64 nesting levels accepted; 100 refused.
func TestValidatePolicy_DepthLimit(t *testing.T) {
	build := func(n int) domain.Condition {
		// Build a deeply nested chain of NOTs ending in a leaf.
		leaf := domain.Condition{Field: "x", Operator: domain.OpEq, Value: "1"}
		out := leaf
		for i := 0; i < n; i++ {
			cur := out
			out = domain.Condition{Not: &cur}
		}
		return out
	}
	pOK := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{{
			RuleID:     "ok",
			Conditions: build(50),
			Effect:     domain.EffectDeny,
		}},
	}
	if err := engine.ValidatePolicy(pOK); err != nil {
		t.Errorf("50-deep nesting refused: %v", err)
	}

	pBad := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{{
			RuleID:     "bad",
			Conditions: build(200),
			Effect:     domain.EffectDeny,
		}},
	}
	if err := engine.ValidatePolicy(pBad); err == nil {
		t.Errorf("200-deep nesting should be refused")
	}
}
