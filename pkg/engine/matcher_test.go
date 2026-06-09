package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestMatchesScope_AllPaths exercises every branch of the scope matcher.
// The headline case (TG-001) pins the bug where a policy scoped only by
// tool_groups was incorrectly matching every tool call because the empty
// ToolNames check short-circuited the whole tool-dimension block.
func TestMatchesScope_AllPaths(t *testing.T) {
	mkEnv := func(orgID, agentID, toolName, toolGroup string) *domain.ActionEnvelope {
		return &domain.ActionEnvelope{
			OrgID:     orgID,
			AgentID:   agentID,
			ToolName:  toolName,
			ToolGroup: toolGroup,
		}
	}

	cases := []struct {
		name  string
		env   *domain.ActionEnvelope
		scope domain.PolicyScope
		want  bool
	}{
		{
			name:  "empty scope matches everything",
			env:   mkEnv("any-org", "any-agent", "any-tool", "any-group"),
			scope: domain.PolicyScope{},
			want:  true,
		},
		{
			name: "tool_names only — matching tool name",
			env:  mkEnv("o", "a", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				ToolNames: []string{"issue_refund"},
			},
			want: true,
		},
		{
			name: "tool_names only — non-matching tool name",
			env:  mkEnv("o", "a", "adjust_balance", "monetary_outflow"),
			scope: domain.PolicyScope{
				ToolNames: []string{"issue_refund"},
			},
			want: false,
		},
		{
			// TG-001 REGRESSION: pre-fix, this returned true (the bug).
			// Post-fix, the unmatched group must cause this to return false.
			name: "tool_groups only — non-matching group must NOT match (TG-001 regression)",
			env:  mkEnv("o", "a", "send_email", "comms"),
			scope: domain.PolicyScope{
				ToolGroups: []string{"monetary_outflow"},
			},
			want: false,
		},
		{
			name: "tool_groups only — matching group",
			env:  mkEnv("o", "a", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				ToolGroups: []string{"monetary_outflow"},
			},
			want: true,
		},
		{
			name: "tool_names + tool_groups — name matches",
			env:  mkEnv("o", "a", "issue_refund", "other"),
			scope: domain.PolicyScope{
				ToolNames:  []string{"issue_refund"},
				ToolGroups: []string{"monetary_outflow"},
			},
			want: true,
		},
		{
			name: "tool_names + tool_groups — group matches (name does not)",
			env:  mkEnv("o", "a", "adjust_balance", "monetary_outflow"),
			scope: domain.PolicyScope{
				ToolNames:  []string{"issue_refund"},
				ToolGroups: []string{"monetary_outflow"},
			},
			want: true,
		},
		{
			name: "tool_names + tool_groups — neither matches",
			env:  mkEnv("o", "a", "send_email", "comms"),
			scope: domain.PolicyScope{
				ToolNames:  []string{"issue_refund"},
				ToolGroups: []string{"monetary_outflow"},
			},
			want: false,
		},
		{
			name: "org_ids — org match required when set",
			env:  mkEnv("other-org", "a", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				OrgIDs:    []string{"acme"},
				ToolNames: []string{"issue_refund"},
			},
			want: false,
		},
		{
			name: "org_ids — matching org passes",
			env:  mkEnv("acme", "a", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				OrgIDs:    []string{"acme"},
				ToolNames: []string{"issue_refund"},
			},
			want: true,
		},
		{
			name: "agent_ids — agent must match when set",
			env:  mkEnv("o", "other-agent", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				AgentIDs:  []string{"support-bot"},
				ToolNames: []string{"issue_refund"},
			},
			want: false,
		},
		{
			name: "agent_ids — matching agent passes",
			env:  mkEnv("o", "support-bot", "issue_refund", "monetary_outflow"),
			scope: domain.PolicyScope{
				AgentIDs:  []string{"support-bot"},
				ToolNames: []string{"issue_refund"},
			},
			want: true,
		},
		{
			name: "tool_groups only — empty env.ToolGroup is not a match",
			env:  mkEnv("o", "a", "issue_refund", ""),
			scope: domain.PolicyScope{
				ToolGroups: []string{"monetary_outflow"},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesScope(tc.env, tc.scope)
			if got != tc.want {
				t.Errorf("matchesScope = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMatchPolicies_FiltersByApproved verifies the top-level filter also
// drops policies that are not in approved status — this is the layer
// callers actually use, and we should pin its contract.
func TestMatchPolicies_FiltersByApproved(t *testing.T) {
	env := &domain.ActionEnvelope{OrgID: "o", AgentID: "a", ToolName: "issue_refund", ToolGroup: "monetary_outflow"}
	approved := domain.Policy{
		PolicyID: "approved",
		Status:   domain.PolicyStatusApproved,
		Scope:    domain.PolicyScope{ToolNames: []string{"issue_refund"}},
	}
	draft := domain.Policy{
		PolicyID: "draft",
		Status:   domain.PolicyStatusDraft,
		Scope:    domain.PolicyScope{ToolNames: []string{"issue_refund"}},
	}
	got := MatchPolicies(env, []domain.Policy{approved, draft})
	if len(got) != 1 || got[0].PolicyID != "approved" {
		t.Fatalf("MatchPolicies should drop non-approved; got %d policies", len(got))
	}
}
