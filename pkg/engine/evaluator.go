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

	// Step 3: Evaluate all rules from all matched policies
	var allResults []domain.RuleResult
	rulesTriggered := 0

	// Track the strictest mode across matched policies
	// If ANY matched policy is in enforcement mode, use enforcement
	effectiveMode := mode
	for _, policy := range matched {
		if policy.Mode == domain.PolicyModeEnforcement {
			effectiveMode = domain.PolicyModeEnforcement
		}
		for _, rule := range policy.Rules {
			// Skip disabled rules
			if !rule.IsEnabled() {
				continue
			}
			result := evaluateRule(rule, policy.PolicyID, policy.Version, fields)
			allResults = append(allResults, result)
			if result.Matched {
				rulesTriggered++
			}
		}
	}

	// Step 4: Resolve overall decision
	decision := domain.DecisionAllowed
	if len(allResults) > 0 {
		decision = ResolveDecision(allResults)
	}

	// Step 5: Resolve action taken (differs in shadow mode)
	actionTaken := ResolveActionTaken(decision, effectiveMode)

	// Step 6: Determine near-miss
	// Near-miss = shadow mode only: the action would have been blocked but was allowed through.
	// In enforcement mode, blocked actions are real blocks, not near-misses.
	isNearMiss := (effectiveMode == domain.PolicyModeShadow) &&
		(decision == domain.DecisionDenied || decision == domain.DecisionEscalated)

	// Step 7: Find primary citation and suggested response
	primaryCitation := FindPrimaryCitation(allResults)
	suggestedResponse := ""
	if decision == domain.DecisionDenied {
		// Collect all rules from matched policies for suggested response lookup
		var allRules []domain.Rule
		for _, policy := range matched {
			for _, rule := range policy.Rules {
				if rule.IsEnabled() {
					allRules = append(allRules, rule)
				}
			}
		}
		suggestedResponse = FindSuggestedResponse(allRules, allResults)
	}

	// Step 8: Generate decision reason
	decisionReason := generateDecisionReason(decision, allResults, effectiveMode)

	return &domain.EvaluationResult{
		Decision:          decision,
		ActionTaken:       actionTaken,
		DecisionReason:    decisionReason,
		EffectiveMode:     effectiveMode,
		PoliciesMatched:   len(matched),
		RulesEvaluated:    len(allResults),
		RulesTriggered:    rulesTriggered,
		RuleResults:       allResults,
		PrimaryCitation:   primaryCitation,
		IsNearMiss:        isNearMiss,
		SuggestedResponse: suggestedResponse,
	}
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
func generateDecisionReason(decision domain.Decision, results []domain.RuleResult, mode domain.PolicyMode) string {
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
	}

	if len(reasons) > 0 {
		return fmt.Sprintf("%s by: %s", prefix, strings.Join(reasons, "; "))
	}
	return fmt.Sprintf("%s by policy rules.", prefix)
}
