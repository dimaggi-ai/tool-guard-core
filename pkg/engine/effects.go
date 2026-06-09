package engine

import (
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ResolveDecision determines the overall decision from triggered rule effects.
// Effect hierarchy: deny > escalate > flag > allow
// Returns the highest-severity decision from all triggered rules.
func ResolveDecision(results []domain.RuleResult) domain.Decision {
	maxSeverity := 0
	for _, r := range results {
		if r.Matched {
			s := domain.EffectSeverity(r.Effect)
			if s > maxSeverity {
				maxSeverity = s
			}
		}
	}

	switch maxSeverity {
	case 4:
		return domain.DecisionDenied
	case 3:
		return domain.DecisionEscalated
	case 2:
		return domain.DecisionFlagged
	default:
		return domain.DecisionAllowed
	}
}

// ResolveActionTaken determines the actual action based on decision and mode.
// In shadow mode, denied/escalated actions are allowed but logged as near-misses.
func ResolveActionTaken(decision domain.Decision, mode domain.PolicyMode) domain.ActionTaken {
	if mode == domain.PolicyModeShadow {
		switch decision {
		case domain.DecisionDenied, domain.DecisionEscalated:
			return domain.ActionAllowedShadow
		case domain.DecisionFlagged:
			return domain.ActionFlagged
		default:
			return domain.ActionAllowed
		}
	}

	// Enforcement mode
	switch decision {
	case domain.DecisionDenied:
		return domain.ActionDenied
	case domain.DecisionEscalated:
		return domain.ActionEscalated
	case domain.DecisionFlagged:
		return domain.ActionFlagged
	default:
		return domain.ActionAllowed
	}
}

// FindPrimaryCitation returns the citation from the highest-severity triggered rule.
func FindPrimaryCitation(results []domain.RuleResult) *domain.Citation {
	var best *domain.Citation
	bestSeverity := 0

	for _, r := range results {
		if r.Matched {
			s := domain.EffectSeverity(r.Effect)
			if s > bestSeverity {
				bestSeverity = s
				c := r.Citation
				best = &c
			}
		}
	}

	return best
}

// FindSuggestedResponse returns the suggested_response from the highest-
// severity deny rule. Looks rules up by RuleID rather than by slice index
// — index-aligned lookups silently break the moment either slice is
// filtered or sorted, so this map-by-ID approach is the defensive default.
func FindSuggestedResponse(rules []domain.Rule, results []domain.RuleResult) string {
	ruleByID := make(map[string]*domain.Rule, len(rules))
	for i := range rules {
		if rules[i].RuleID != "" {
			ruleByID[rules[i].RuleID] = &rules[i]
		}
	}

	bestSeverity := 0
	var response string
	for _, r := range results {
		if !r.Matched || r.Effect != domain.EffectDeny {
			continue
		}
		s := domain.EffectSeverity(r.Effect)
		if s <= bestSeverity {
			continue
		}
		bestSeverity = s
		if rule, ok := ruleByID[r.RuleID]; ok {
			response = rule.EffectConfig.SuggestedResponse
		}
	}
	return response
}
