package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// TestCodingAgentWritesSelfProtection exercises the new shipped-policy
// behavior directly rather than adding it to the cross-version conformance
// corpus: v0.3.0/v0.4.0 policy snapshots intentionally predate this rule.
func TestCodingAgentWritesSelfProtection(t *testing.T) {
	policyPath := filepath.Join("..", "..", "policies", "coding_agent_writes.yaml")
	policy, err := loadPolicyYAML(policyPath)
	if err != nil {
		t.Fatalf("load shipped policy: %v", err)
	}
	if err := engine.ValidatePolicy(&policy); err != nil {
		t.Fatalf("validate shipped policy: %v", err)
	}

	tests := []struct {
		name       string
		tool       string
		parameters map[string]any
		want       domain.Decision
	}{
		{
			name: "deny policy self modification via file_path",
			tool: "edit",
			parameters: map[string]any{
				"file_path":  "/home/user/project/policies/coding_agent_writes.yaml",
				"old_string": "mode: enforcement",
				"new_string": "mode: shadow",
			},
			want: domain.DecisionDenied,
		},
		{
			name: "deny audit tampering via path alias",
			tool: "write",
			parameters: map[string]any{
				"path":    "/home/user/.claude/tg-guard-audit.jsonl",
				"content": "",
			},
			want: domain.DecisionDenied,
		},
		{
			name: "allow ordinary source edit",
			tool: "edit",
			parameters: map[string]any{
				"file_path":  "/home/user/project/main.go",
				"old_string": "old",
				"new_string": "new",
			},
			want: domain.DecisionAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.parameters)
			if err != nil {
				t.Fatalf("marshal parameters: %v", err)
			}
			env := domain.ActionEnvelope{
				EnvelopeID: "self-protect-" + tc.name,
				Timestamp:  time.Now().UTC(),
				ToolName:   tc.tool,
				ToolGroup:  "filesystem_writes",
				Parameters: raw,
			}
			result := engine.NewEvaluator().Evaluate(
				&env,
				[]domain.Policy{policy},
				domain.PolicyModeEnforcement,
			)
			if result.Decision != tc.want {
				t.Fatalf("decision = %q, want %q (reason: %s)",
					result.Decision, tc.want, result.DecisionReason)
			}
		})
	}
}

func TestCodingAgentGuardBlocksRecursiveRootDelete(t *testing.T) {
	policyPath := filepath.Join("..", "..", "examples", "coding-agent-guard", "policy.yaml")
	policy, err := loadPolicyYAML(policyPath)
	if err != nil {
		t.Fatalf("load coding-agent policy: %v", err)
	}
	if err := engine.ValidatePolicy(&policy); err != nil {
		t.Fatalf("validate coding-agent policy: %v", err)
	}
	parameters, _ := json.Marshal(map[string]any{"command": "rm -rf /"})
	envelope := domain.ActionEnvelope{
		EnvelopeID: "root-delete-regression",
		Timestamp:  time.Now().UTC(),
		ToolName:   "bash",
		ToolGroup:  "shell",
		Parameters: parameters,
	}
	result := engine.NewEvaluator().Evaluate(&envelope, []domain.Policy{policy}, domain.PolicyModeEnforcement)
	if result.Decision != domain.DecisionDenied {
		t.Fatalf("rm -rf / decision=%q, want denied (reason: %s)", result.Decision, result.DecisionReason)
	}
}
