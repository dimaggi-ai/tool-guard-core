package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// Evaluator is the core policy evaluation engine.
// It is pure logic with no I/O — all data is passed in.
type Evaluator struct{}

// NewEvaluator creates a new policy evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate processes an envelope against all applicable policies and returns the result.
func (e *Evaluator) Evaluate(envelope *domain.ActionEnvelope, policies []domain.Policy, mode domain.PolicyMode) *domain.EvaluationResult {
	// Step 1: Match policies by scope
	matched := MatchPolicies(envelope, policies)

	// Step 1b: Sort matched policies by priority (lower number = higher priority, default 100)
	sort.Slice(matched, func(i, j int) bool {
		pi := matched[i].Priority
		pj := matched[j].Priority
		if pi == 0 {
			pi = 100
		}
		if pj == 0 {
			pj = 100
		}
		return pi < pj
	})

	// Step 2: Flatten envelope to field map for condition evaluation
	fields := FlattenEnvelope(envelope)

	// Step 3: Evaluate all rules from all matched policies, recording each
	// policy's mode so enforcement and shadow effects can be resolved separately.
	var allResults []domain.RuleResult
	var enforcedResults []domain.RuleResult
	rulesTriggered := 0
	shadowEffectMatched := false
	shadowGatingMatched := false
	for _, policy := range matched {
		for _, rule := range policy.Rules {
			// Skip disabled rules
			if !rule.IsEnabled() {
				continue
			}
			result := evaluateRule(rule, policy.PolicyID, policy.Version, fields)
			allResults = append(allResults, result)
			if result.Matched {
				rulesTriggered++
				// Treat every non-shadow value as enforcement. Loaders reject invalid
				// modes, but direct engine callers still fail closed.
				if policy.Mode != domain.PolicyModeShadow {
					enforcedResults = append(enforcedResults, result)
				} else {
					shadowEffectMatched = true
					if result.Effect == domain.EffectDeny || result.Effect == domain.EffectEscalate {
						shadowGatingMatched = true
					}
				}
			}
		}
	}

	// Step 4: Resolve overall decision (max effect severity, order-independent).
	decision := domain.DecisionAllowed
	if len(allResults) > 0 {
		decision = ResolveDecision(allResults)
	}

	// Step 5: Resolve what actually controls the action. Policy mode owns each
	// policy's contribution: a shadow policy is telemetry even when the call site
	// defaults to enforcement, while an enforcement policy cannot be downgraded
	// by a shadow call site. Resolve enforcement effects independently so a
	// higher-severity shadow deny cannot suppress a lower-severity enforcement
	// escalation and let the action run.
	enforcedDecision := ResolveDecision(enforcedResults)
	actionDecision := enforcedDecision
	effectiveMode := domain.PolicyModeEnforcement // unknown modes fail closed
	if enforcedDecision == domain.DecisionAllowed {
		actionDecision = decision
		// Loaders and CLI/HTTP entry points reject invalid modes, but Evaluate is
		// also a public Go API. Preserve its fail-closed boundary: only the two
		// known call-site modes may allow a shadow contribution to become
		// observe-only. An unknown direct-call value stays enforcement.
		validCallSiteMode := mode == domain.PolicyModeShadow || mode == domain.PolicyModeEnforcement
		if validCallSiteMode && (shadowEffectMatched || mode == domain.PolicyModeShadow) {
			effectiveMode = domain.PolicyModeShadow
		}
	}

	// Step 6: Resolve action taken (differs in shadow mode)
	actionTaken := ResolveActionTaken(actionDecision, effectiveMode)

	// Step 7: Determine near-miss
	// A near-miss records a matched shadow deny/escalate that was not itself
	// applied. It can coexist with a different enforcement-policy action (for
	// example, a shadow deny observed while the floor escalates the same call).
	isNearMiss := shadowGatingMatched

	// Step 8: Find primary citation and suggested response
	primaryCitation := FindPrimaryCitation(allResults)
	// Keep aggregate decision provenance separate from the rules that control
	// execution. A higher-severity shadow rule can own Decision while a lower-
	// severity enforcement rule owns ActionTaken; operational consumers must
	// explain the latter when asking a human to approve or blocking a call.
	appliedResults := enforcedResults
	if enforcedDecision == domain.DecisionAllowed &&
		(actionTaken == domain.ActionDenied || actionTaken == domain.ActionEscalated || actionTaken == domain.ActionFlagged) {
		// Covers shadow flags (which are applied telemetry) and the public Go
		// API's fail-closed handling of an invalid call-site mode.
		appliedResults = matchedRuleResults(allResults)
	}
	appliedPrimaryCitation := FindPrimaryCitation(appliedResults)
	suggestedResponse := ""
	if decision != domain.DecisionAllowed {
		guidanceResults := appliedResults
		if actionTaken == domain.ActionAllowedShadow {
			// No gating policy controlled execution, so retain the raw shadow
			// guidance as observe-only telemetry.
			guidanceResults = allResults
		}
		suggestedResponse = findPolicySuggestedResponse(matched, guidanceResults)
	}

	// Step 9: Generate decision reason
	decisionReason := generateDecisionReason(decision, actionDecision, allResults, effectiveMode)

	return &domain.EvaluationResult{
		Decision:               decision,
		ActionTaken:            actionTaken,
		DecisionReason:         decisionReason,
		EffectiveMode:          effectiveMode,
		PoliciesMatched:        len(matched),
		RulesEvaluated:         len(allResults),
		RulesTriggered:         rulesTriggered,
		RuleResults:            allResults,
		AppliedRuleResults:     appliedResults,
		PrimaryCitation:        primaryCitation,
		AppliedPrimaryCitation: appliedPrimaryCitation,
		IsNearMiss:             isNearMiss,
		SuggestedResponse:      suggestedResponse,
	}
}

func matchedRuleResults(results []domain.RuleResult) []domain.RuleResult {
	matched := make([]domain.RuleResult, 0, len(results))
	for _, result := range results {
		if result.Matched {
			matched = append(matched, result)
		}
	}
	return matched
}

type policyRuleKey struct {
	policyID      string
	policyVersion int
	ruleID        string
}

// findPolicySuggestedResponse resolves guidance from the exact policy rule
// that controls the selected result set. Rule IDs are not globally unique, so
// policy ID and version are part of the key.
func findPolicySuggestedResponse(policies []domain.Policy, results []domain.RuleResult) string {
	responses := make(map[policyRuleKey]string)
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if !rule.IsEnabled() {
				continue
			}
			responses[policyRuleKey{policy.PolicyID, policy.Version, rule.RuleID}] = rule.EffectConfig.SuggestedResponse
		}
	}

	bestSeverity := 0
	response := ""
	for _, result := range results {
		if !result.Matched {
			continue
		}
		severity := domain.EffectSeverity(result.Effect)
		if severity <= bestSeverity {
			continue
		}
		bestSeverity = severity
		response = responses[policyRuleKey{result.PolicyID, result.PolicyVersion, result.RuleID}]
	}
	return response
}

// evaluateRule evaluates a single rule against the flattened field map.
// The diagnostic returned by classifier leaves (sql_classify parse
// errors, mutating-CTE flag triggers, etc.) is surfaced via
// RuleResult.Details so operators see "WHY" in the audit chain.
func evaluateRule(rule domain.Rule, policyID string, policyVersion int, fields map[string]interface{}) domain.RuleResult {
	matched, detail := EvalConditionWithDetail(rule.Conditions, fields)

	return domain.RuleResult{
		RuleID:        rule.RuleID,
		RuleName:      rule.Name,
		PolicyID:      policyID,
		PolicyVersion: policyVersion,
		Matched:       matched,
		Effect:        rule.Effect,
		Severity:      rule.EffectConfig.Severity,
		Citation:      rule.Citation,
		Details:       detail,
	}
}

// generateDecisionReason builds a human-readable explanation of the decision.
func generateDecisionReason(decision, actionDecision domain.Decision, results []domain.RuleResult, mode domain.PolicyMode) string {
	if decision == domain.DecisionAllowed {
		triggered := 0
		for _, r := range results {
			if r.Matched {
				triggered++
			}
		}
		if triggered == 0 {
			return "No rules triggered; action permitted."
		}
		return "Action permitted; all triggered rules allow this action."
	}

	var reasons []string
	for _, r := range results {
		if r.Matched && domain.EffectSeverity(r.Effect) >= 2 {
			reasons = append(reasons, fmt.Sprintf("[%s] %s (effect: %s)", r.RuleID, r.RuleName, r.Effect))
		}
	}

	prefix := ""
	switch decision {
	case domain.DecisionDenied:
		prefix = "Denied"
	case domain.DecisionEscalated:
		prefix = "Escalated"
	case domain.DecisionFlagged:
		prefix = "Flagged"
	}

	if mode == domain.PolicyModeShadow {
		prefix += " (shadow mode — action was allowed)"
	} else if actionDecision != decision {
		prefix += fmt.Sprintf(" (enforced action: %s)", actionDecision)
	}

	if len(reasons) > 0 {
		return fmt.Sprintf("%s by: %s", prefix, strings.Join(reasons, "; "))
	}
	return fmt.Sprintf("%s by policy rules.", prefix)
}
