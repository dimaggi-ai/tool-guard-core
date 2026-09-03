package engine

import (
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// MatchPolicies filters policies that apply to the given envelope.
// Only approved policies are evaluated.
func MatchPolicies(envelope *domain.ActionEnvelope, policies []domain.Policy) []domain.Policy {
	var matched []domain.Policy
	for _, p := range policies {
		if p.Status != domain.PolicyStatusApproved {
			continue
		}
		if matchesScope(envelope, p.Scope) {
			matched = append(matched, p)
		}
	}
	return matched
}

// matchesScope checks if an envelope falls within a policy's scope. Empty scope fields
// mean "match all" for that dimension; the policy matches when every set scope
// dimension matches. The tool dimension is satisfied if EITHER ToolNames or ToolGroups
// matches when at least one is set, because a policy author who scopes only by
// tool_group must NOT also match every tool call (regression TG-001; pinned by
// TestMatchesScope_AllPaths).
func matchesScope(env *domain.ActionEnvelope, scope domain.PolicyScope) bool {
	if len(scope.OrgIDs) > 0 && !containsStr(scope.OrgIDs, env.OrgID) {
		return false
	}
	if len(scope.AgentIDs) > 0 && !containsStr(scope.AgentIDs, env.AgentID) {
		return false
	}

	// Tool dimension: scope is satisfied if any set tool selector matches.
	// If neither ToolNames nor ToolGroups is set, the tool dimension is
	// open ("match all tools"); when one is set, that selector gates.
	if len(scope.ToolNames) > 0 || len(scope.ToolGroups) > 0 {
		toolMatched := false
		if len(scope.ToolNames) > 0 && containsStrFold(scope.ToolNames, env.ToolName) {
			toolMatched = true
		}
		if !toolMatched && len(scope.ToolGroups) > 0 && env.ToolGroup != "" && containsStr(scope.ToolGroups, env.ToolGroup) {
			toolMatched = true
		}
		if !toolMatched {
			return false
		}
	}

	return true
}

// ToolNameKnown reports whether toolName is explicitly declared in
// scope.tool_names of any loaded ENFORCEMENT policy. Backs the
// -unknown-tools-deny posture (tg-proxy and tg hook both use it) to refuse
// evaluation of name variants the operator never authorised — e.g. a
// tool_group-scoped write policy governs "write"/"edit"/"multiedit", but a
// brand-new tool name the agent starts calling ("write_v2") matches no
// tool_names anywhere and would otherwise pass ungoverned by default.
// Shadow-mode policies are excluded — a shadow rollout that lists a tool
// "for observation" must NOT make the unknown-tools gate pass, since
// nothing is actually enforcing on it yet. Draft/pending/archived policies
// are excluded too, mirroring MatchPolicies' own approval-status filter:
// a draft enforcement-mode policy that merely lists a dangerous tool name
// in its scope will never actually be matched or applied (MatchPolicies
// filters it out), so letting it count here would make ToolNameKnown
// report "known" for a name that in reality has zero policies governing
// it — the call then sails through allowed with PoliciesMatched=0,
// silently defeating -unknown-tools-deny for any tool name that merely
// appears in SOME non-approved policy anywhere in the org's policy set.
//
// Deliberately EXACT-match (containsStr), not case-insensitive, unlike
// matchesScope's tool_names check below. This is not an inconsistency:
// matchesScope's job is "apply an already-declared policy's own rules to
// a real call", where case-insensitivity closes a real gap (different
// agent frameworks capitalize tool names differently). ToolNameKnown's
// job is the opposite - "is this EXACTLY one of the names the operator
// explicitly, deliberately declared, or should we fail closed and deny
// it as unrecognized" - and unrecognized-name spoofing via case variation
// ("DROP_TABLE" vs. a declared "drop_table") is exactly the kind of thing
// this fail-closed default exists to catch. Confirmed by a real
// regression: making this case-insensitive let examples/postgres-attack's
// bruteforce-policies.sh's "Tool-name variant spoofing" cases
// (DROP_TABLE, Drop_Table) slip past -unknown-tools-deny and evaluate as
// allowed, where the exact-match version correctly fails closed and
// denies them as unrecognized. Do not change this back without re-running
// `make test-postgres-full` and confirming zero bypasses.
//
// Exported (moved here from cmd/tg-proxy) so both first-class enforcement
// points share ONE definition instead of two copies that could silently
// drift apart.
func ToolNameKnown(toolName string, policies []domain.Policy) bool {
	if toolName == "" {
		return false
	}
	for _, p := range policies {
		if p.Status != domain.PolicyStatusApproved {
			continue
		}
		if p.Mode != domain.PolicyModeEnforcement {
			continue
		}
		if containsStr(p.Scope.ToolNames, toolName) {
			return true
		}
	}
	return false
}

func containsStr(list []string, val string) bool {
	for _, s := range list {
		if s == val {
			return true
		}
	}
	return false
}

// containsStrFold is containsStr with a case-insensitive comparison, used
// ONLY by matchesScope's tool_names check - deliberately NOT by
// ToolNameKnown (see its doc comment for why that stays exact-match).
// env.ToolName is untrusted, externally-sourced data, and real agent
// frameworks are inconsistent about its casing - Claude Code sends "Bash",
// other integrations send "bash" - so a policy authored against one casing
// must still govern a call that arrives with a different one, or the
// policy silently never matches and the call passes ungoverned with
// PoliciesMatched=0 (found via a real dogfood deployment: an enforcement
// policy scoped to lowercase tool_names never matched "Bash", so `rm -rf /`
// evaluated as allowed). Also not used for OrgIDs/AgentIDs (identifiers
// where case carries real meaning) or ToolGroups (an operator-assigned
// constant, not raw agent-supplied input, so it doesn't have the same
// organic case-variance problem).
func containsStrFold(list []string, val string) bool {
	for _, s := range list {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
