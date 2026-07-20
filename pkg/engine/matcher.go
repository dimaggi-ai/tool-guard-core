package engine

import (
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

// matchesScope checks if an envelope falls within a policy's scope.
// Empty scope fields mean "match all" for that dimension; the policy
// matches when every set scope dimension matches. The tool dimension is
// satisfied if EITHER ToolNames or ToolGroups matches when at least one
// is set — important because a policy author who scopes only by
// tool_group must NOT also match every tool call (regression TG-001;
// pinned by TestMatchesScope_AllPaths).
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
		if len(scope.ToolNames) > 0 && containsStr(scope.ToolNames, env.ToolName) {
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
// nothing is actually enforcing on it yet.
//
// Exported (moved here from cmd/tg-proxy) so both first-class enforcement
// points share ONE definition instead of two copies that could silently
// drift apart.
func ToolNameKnown(toolName string, policies []domain.Policy) bool {
	if toolName == "" {
		return false
	}
	for _, p := range policies {
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
