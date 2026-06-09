package main

import (
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestGolden_LintPublicExample pins the exact lint rule names emitted on
// the policy the README and docs/battle-test-results.md publicly cite as
// the canonical example. If a future refactor renames a heuristic or
// changes when it fires, this test breaks the build BEFORE the public
// docs become wrong — pairs with TestGolden_AllLintRulesHaveStableNames
// to catch the full class of doc-vs-CLI drift.
func TestGolden_LintPublicExample(t *testing.T) {
	policy, err := loadPolicyYAML(filepath.Join("..", "..", "policies", "refund_cap.yaml"))
	if err != nil {
		t.Fatalf("load example policy: %v", err)
	}
	findings := lintPolicy(policy)

	// The README's Quick start section lists these two warnings verbatim.
	// If you rename either, the README needs the same edit; this assert
	// forces that consistency.
	want := map[string]struct{}{
		"scope-no-tool-group":           {},
		"amount-without-semantic-check": {},
	}
	got := map[string]struct{}{}
	for _, f := range findings {
		got[f.Rule] = struct{}{}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("README cites %q as a lint warning on policies/refund_cap.yaml, but it did not fire", name)
		}
	}
	// The example policy must NOT trigger anything classified "error".
	// If it does, the README's "$ tg lint ... exit code 0" promise is
	// silently broken.
	for _, f := range findings {
		if f.Severity == "error" {
			t.Errorf("public example policy raised an ERROR finding (%q); the README and lint exit-code documentation expect only warnings", f.Rule)
		}
	}
}

// TestGolden_LintStrictPolicyClean pins the README's promise that
// policies/refund_cap_strict.yaml lints clean (no findings at all). The
// strict variant carries both mitigations the lint asks for:
//   - explicit tool_groups + tool_names scope (suppresses
//     scope-no-tool-group)
//   - a compiling regex tripwire on parameters.reason (suppresses
//     amount-without-semantic-check)
//
// If either suppression breaks, this test fails before the README is
// silently wrong.
func TestGolden_LintStrictPolicyClean(t *testing.T) {
	policy, err := loadPolicyYAML(filepath.Join("..", "..", "policies", "refund_cap_strict.yaml"))
	if err != nil {
		t.Fatalf("load strict policy: %v", err)
	}
	findings := lintPolicy(policy)
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("strict policy lint should be clean per README; got %q (%s): %s", f.Rule, f.Severity, f.Message)
		}
	}
}

// TestGolden_AllLintRulesHaveStableNames pins the closed set of lint
// rule names. README and battle-test-results.md cite specific names; if
// any of them is renamed or removed without the docs being updated, this
// test fails so the author has to address both at the same time.
func TestGolden_AllLintRulesHaveStableNames(t *testing.T) {
	// Construct a policy that triggers every heuristic at least once.
	tripEverything := domain.Policy{
		Scope: domain.PolicyScope{}, // → policy-scope-leak
		Rules: []domain.Rule{
			{
				RuleID: "dup",
				Conditions: domain.Condition{
					Field:    "amount", // → amount-without-semantic-check
					Operator: domain.OpGt,
					Value:    float64(100),
				},
				Effect: domain.EffectDeny,
				// no citation                       // → rule-missing-citation
			},
			{
				RuleID: "dup", // → rule-id-collision
				Conditions: domain.Condition{
					Field:    "x",
					Operator: domain.OpRegex,
					Value:    "[unclosed", // → invalid-regex-syntax
				},
				Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
			},
			{
				RuleID: "r3",
				Conditions: domain.Condition{
					Field:    "x",
					Operator: "totally_made_up", // → unknown-operator
					Value:    1,
				},
				Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
			},
		},
	}
	findings := lintPolicy(tripEverything)
	want := map[string]bool{
		"policy-scope-leak":             false,
		"amount-without-semantic-check": false,
		"rule-missing-citation":         false,
		"rule-id-collision":             false,
		"invalid-regex-syntax":          false,
		"unknown-operator":              false,
	}
	for _, f := range findings {
		if _, ok := want[f.Rule]; ok {
			want[f.Rule] = true
		}
	}
	for name, hit := range want {
		if !hit {
			t.Errorf("expected lint rule %q to fire (renamed or removed?)", name)
		}
	}
}
