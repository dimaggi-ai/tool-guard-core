package main

import (
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ── E: writable-scope-no-self-protection heuristic ────────────────────────

// TestLint_WritableScopeNoSelfProtection_Fires asserts that a policy
// admitting write-capable tools but containing no path_classify deny rule
// triggers the new lint warning.
func TestLint_WritableScopeNoSelfProtection_Fires(t *testing.T) {
	cases := []struct {
		name       string
		toolNames  []string
		toolGroups []string
	}{
		{
			name:      "single bash in scope",
			toolNames: []string{"bash"},
		},
		{
			name:      "write in scope",
			toolNames: []string{"write"},
		},
		{
			name:      "edit in scope",
			toolNames: []string{"edit"},
		},
		{
			name:      "notebookedit in scope",
			toolNames: []string{"notebookedit"},
		},
		{
			name:      "run_command in scope",
			toolNames: []string{"run_command"},
		},
		{
			name:      "multiple write tools in scope",
			toolNames: []string{"bash", "write", "edit"},
		},
		{
			name:       "empty scope (matches everything, including writable tools)",
			toolNames:  nil,
			toolGroups: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := domain.Policy{
				Scope: domain.PolicyScope{
					ToolNames:  tc.toolNames,
					ToolGroups: tc.toolGroups,
				},
				Rules: []domain.Rule{
					{
						RuleID: "some-deny",
						Conditions: domain.Condition{
							Field:    "parameters.command",
							Operator: domain.OpRegex,
							Value:    `rm\s+-rf`,
						},
						Effect:   domain.EffectDeny,
						Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
					},
				},
			}
			found := false
			for _, f := range lintPolicy(p) {
				if f.Rule == "writable-scope-no-self-protection" {
					found = true
					if f.Severity != "warn" {
						t.Errorf("writable-scope-no-self-protection must be warn severity, got %q", f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("case %q: expected writable-scope-no-self-protection to fire on a write-scoped policy with no path_classify, but it did not", tc.name)
			}
		})
	}
}

// TestLint_WritableScopeNoSelfProtection_SuppressedByPathClassify asserts
// that the heuristic is suppressed when a deny rule uses a path_classify leaf.
func TestLint_WritableScopeNoSelfProtection_SuppressedByPathClassify(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames: []string{"bash", "write"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "path-guard",
				Conditions: domain.Condition{
					PathClassify: &domain.PathClassify{
						Field: "parameters.file_path",
						Require: domain.PathRequire{
							DeniedCanonicalPrefixes: []string{"/etc/", "/opt/policies/"},
						},
					},
				},
				Effect:   domain.EffectDeny,
				Citation: domain.Citation{DocumentID: "d", Excerpt: "protect etc"},
			},
		},
	}
	for _, f := range lintPolicy(p) {
		if f.Rule == "writable-scope-no-self-protection" {
			t.Errorf("heuristic must be suppressed when a deny rule uses path_classify; got finding: %q", f.Message)
		}
	}
}

// TestLint_WritableScopeNoSelfProtection_EscalateAlsoSuppresses verifies
// that an escalate rule with path_classify is also sufficient to suppress
// the heuristic (not just deny).
func TestLint_WritableScopeNoSelfProtection_EscalateAlsoSuppresses(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames: []string{"bash"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "path-escalate",
				Conditions: domain.Condition{
					PathClassify: &domain.PathClassify{
						Field: "parameters.path",
						Require: domain.PathRequire{
							DeniedCanonicalPrefixes: []string{"/etc/"},
						},
					},
				},
				Effect:   domain.EffectEscalate,
				Citation: domain.Citation{DocumentID: "d", Excerpt: "escalate for /etc"},
			},
		},
	}
	for _, f := range lintPolicy(p) {
		if f.Rule == "writable-scope-no-self-protection" {
			t.Errorf("escalate rule with path_classify must also suppress heuristic; got: %q", f.Message)
		}
	}
}

// TestLint_WritableScopeNoSelfProtection_NotFiredByReadOnlyTools verifies
// that a policy scoped to non-writable tools (e.g. read, grep) does NOT
// trigger the heuristic.
func TestLint_WritableScopeNoSelfProtection_NotFiredByReadOnlyTools(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames: []string{"read", "grep", "glob"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "r1",
				Conditions: domain.Condition{
					Field:    "tool_name",
					Operator: domain.OpEq,
					Value:    "read",
				},
				Effect:   domain.EffectFlag,
				Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
			},
		},
	}
	for _, f := range lintPolicy(p) {
		if f.Rule == "writable-scope-no-self-protection" {
			t.Errorf("read-only tool scope should not trigger heuristic; got: %q", f.Message)
		}
	}
}

// TestLint_WritableScopeNoSelfProtection_ShippedRefundPoliciesClean asserts
// that the two shipped example policies (refund_cap and refund_cap_strict)
// do NOT trigger the heuristic — they use non-writable tools (issue_refund).
// This is the explicit "must NOT fire" requirement from the spec.
func TestLint_WritableScopeNoSelfProtection_ShippedRefundPoliciesClean(t *testing.T) {
	for _, name := range []string{"refund_cap.yaml", "refund_cap_strict.yaml"} {
		t.Run(name, func(t *testing.T) {
			policy, err := loadPolicyYAML(filepath.Join("..", "..", "policies", name))
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			for _, f := range lintPolicy(policy) {
				if f.Rule == "writable-scope-no-self-protection" {
					t.Errorf("%s must NOT trigger writable-scope-no-self-protection (issue_refund is not a write tool); got: %q", name, f.Message)
				}
			}
		})
	}
}

// TestLint_WritableScopeNoSelfProtection_AllowRulePathClassifyNotSufficient
// verifies that a path_classify on an ALLOW (not deny/escalate) rule does NOT
// suppress the warning — an allow rule can't protect anything.
func TestLint_WritableScopeNoSelfProtection_AllowRulePathClassifyNotSufficient(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames: []string{"bash"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "allow-with-path",
				Conditions: domain.Condition{
					PathClassify: &domain.PathClassify{
						Field: "parameters.path",
						Require: domain.PathRequire{
							AllowedCanonicalPrefixes: []string{"/tmp/"},
						},
					},
				},
				Effect:   domain.EffectAllow, // allow rule — does NOT suppress the heuristic
				Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
			},
		},
	}
	found := false
	for _, f := range lintPolicy(p) {
		if f.Rule == "writable-scope-no-self-protection" {
			found = true
		}
	}
	if !found {
		t.Error("allow rule with path_classify must NOT suppress the heuristic — only deny/escalate rules count")
	}
}
