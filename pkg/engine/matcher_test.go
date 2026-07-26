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
		{
			// Real-world regression: a dogfood policy scoped tool_names to
			// lowercase ("bash") but Claude Code's own tool_name is "Bash"
			// (capitalized) - PoliciesMatched stayed 0 for every call, so an
			// enforcement policy with a real deny-rm-root rule silently never
			// fired. env.ToolName is untrusted, externally-sourced data;
			// different agent frameworks capitalize it differently, so the
			// match must be case-insensitive.
			name: "tool_names — case-insensitive match (capitalized agent tool name vs lowercase policy)",
			env:  mkEnv("o", "a", "Bash", ""),
			scope: domain.PolicyScope{
				ToolNames: []string{"bash"},
			},
			want: true,
		},
		{
			name: "tool_names — case-insensitive match (lowercase agent tool name vs capitalized policy)",
			env:  mkEnv("o", "a", "bash", ""),
			scope: domain.PolicyScope{
				ToolNames: []string{"Bash"},
			},
			want: true,
		},
		{
			name: "tool_names — case-insensitive match does not widen to a genuinely different tool",
			env:  mkEnv("o", "a", "Bashful", ""),
			scope: domain.PolicyScope{
				ToolNames: []string{"bash"},
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

// TestToolNameKnown_ExactMatchOnly pins that ToolNameKnown stays
// case-SENSITIVE, deliberately unlike matchesScope's tool_names check.
// This is a security regression guard, not an oversight: making this
// case-insensitive (as an earlier version of this fix did, briefly)
// let examples/postgres-attack's bruteforce-policies.sh "Tool-name
// variant spoofing" cases (DROP_TABLE / Drop_Table vs. a declared
// "drop_table") slip past -unknown-tools-deny's fail-closed default and
// evaluate as allowed - confirmed by a real bypass in that suite. Do not
// change this to containsStrFold without re-running
// `make test-postgres-full` and confirming zero bypasses.
func TestToolNameKnown_ExactMatchOnly(t *testing.T) {
	enforcement := domain.Policy{
		PolicyID: "p1",
		Status:   domain.PolicyStatusApproved,
		Mode:     domain.PolicyModeEnforcement,
		Scope:    domain.PolicyScope{ToolNames: []string{"bash"}},
	}
	shadow := domain.Policy{
		PolicyID: "p2",
		Status:   domain.PolicyStatusApproved,
		Mode:     domain.PolicyModeShadow,
		Scope:    domain.PolicyScope{ToolNames: []string{"grep"}},
	}
	policies := []domain.Policy{enforcement, shadow}

	if !ToolNameKnown("bash", policies) {
		t.Error(`ToolNameKnown("bash") = false, want true (exact match against enforcement policy's "bash")`)
	}
	if ToolNameKnown("Bash", policies) {
		t.Error(`ToolNameKnown("Bash") = true, want false — must stay case-SENSITIVE (regression guard: a case variant of a declared name must NOT count as "known", or -unknown-tools-deny's fail-closed default silently stops catching case-spoofed tool names)`)
	}
	if ToolNameKnown("grep", policies) {
		t.Error(`ToolNameKnown("grep") = true, want false (only a shadow-mode policy declares it, shadow must not count)`)
	}
	if ToolNameKnown("write", policies) {
		t.Error(`ToolNameKnown("write") = true, want false (no policy declares it at all)`)
	}
	if ToolNameKnown("", policies) {
		t.Error(`ToolNameKnown("") = true, want false`)
	}
}

// TestToolNameKnown_ExcludesNonApprovedStatus pins that ToolNameKnown
// filters on Status == Approved, mirroring MatchPolicies. A draft (or
// review/archived) enforcement-mode policy that merely lists a dangerous
// tool name in its scope will never actually be matched or enforced —
// MatchPolicies filters it out — so it must not count as "known" here
// either. Before this filter existed, a draft policy naming a tool made
// -unknown-tools-deny treat that name as recognized while zero policies
// actually governed it: the real call sailed through allowed with
// PoliciesMatched=0, silently defeating the fail-closed default for any
// tool name appearing in any draft/pending/archived policy anywhere in
// the org's policy set. Found by an independent adversarial review ahead
// of the v0.5.2 release.
func TestToolNameKnown_ExcludesNonApprovedStatus(t *testing.T) {
	draft := domain.Policy{
		PolicyID: "p1",
		Status:   domain.PolicyStatusDraft,
		Mode:     domain.PolicyModeEnforcement,
		Scope:    domain.PolicyScope{ToolNames: []string{"drop_table"}},
	}
	policies := []domain.Policy{draft}

	if ToolNameKnown("drop_table", policies) {
		t.Error(`ToolNameKnown("drop_table") = true, want false — a draft-status policy must not count as "known"; MatchPolicies would filter it out, so ToolNameKnown reporting it as known makes -unknown-tools-deny wrongly let the call through as if a real policy governed it`)
	}
	matched := MatchPolicies(&domain.ActionEnvelope{ToolName: "drop_table"}, policies)
	if len(matched) != 0 {
		t.Fatalf("sanity check failed: MatchPolicies matched %d policies for a draft policy, want 0", len(matched))
	}
}
