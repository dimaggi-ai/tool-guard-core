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

func containsStr(list []string, val string) bool {
	for _, s := range list {
		if s == val {
			return true
		}
	}
	return false
}
