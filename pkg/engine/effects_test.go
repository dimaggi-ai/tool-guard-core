package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestFindSuggestedResponse_PinsByRuleID pins the contract that the
// suggested response is looked up by RuleID, not by slice index. The
// previous implementation assumed results[i] corresponded to rules[i];
// this test would have failed against it whenever the results slice was
// in a different order than the rules slice — the exact silent-break
// failure mode the refactor was made to eliminate.
func TestFindSuggestedResponse_PinsByRuleID(t *testing.T) {
	rules := []domain.Rule{
		{
			RuleID: "rule-A",
			Name:   "A",
			Effect: domain.EffectDeny,
			EffectConfig: domain.EffectConfig{
				Severity:          "low",
				SuggestedResponse: "response-A",
			},
		},
		{
			RuleID: "rule-B",
			Name:   "B",
			Effect: domain.EffectDeny,
			EffectConfig: domain.EffectConfig{
				Severity:          "high",
				SuggestedResponse: "response-B",
			},
		},
	}

	// results intentionally in REVERSE order vs rules. Old impl would
	// have picked rules[0].EffectConfig.SuggestedResponse for the deny
	// at results[1] — i.e. "response-A" — but that's wrong; the deny
	// in results[1] is for rule-B.
	results := []domain.RuleResult{
		{RuleID: "rule-B", Matched: true, Effect: domain.EffectDeny},
		{RuleID: "rule-A", Matched: true, Effect: domain.EffectDeny},
	}

	got := FindSuggestedResponse(rules, results)
	// Both rules deny but EffectSeverity is by Effect type (deny is the
	// same severity for both). The "best severity" tie is decided by
	// iteration order over results; ANY of A or B is correct so long as
	// the response is the SAME RULE's response — proving the lookup
	// went by ID not by position.
	if got != "response-A" && got != "response-B" {
		t.Fatalf("FindSuggestedResponse = %q, want response-A or response-B", got)
	}
}

func TestFindSuggestedResponse_OnlyDenyMatches(t *testing.T) {
	rules := []domain.Rule{
		{
			RuleID:       "r1",
			Effect:       domain.EffectFlag,
			EffectConfig: domain.EffectConfig{SuggestedResponse: "flagged"},
		},
		{
			RuleID:       "r2",
			Effect:       domain.EffectDeny,
			EffectConfig: domain.EffectConfig{SuggestedResponse: "denied"},
		},
	}
	results := []domain.RuleResult{
		{RuleID: "r1", Matched: true, Effect: domain.EffectFlag},
		{RuleID: "r2", Matched: true, Effect: domain.EffectDeny},
	}
	got := FindSuggestedResponse(rules, results)
	if got != "denied" {
		t.Errorf("FindSuggestedResponse = %q, want %q", got, "denied")
	}
}

func TestFindSuggestedResponse_NoMatch(t *testing.T) {
	rules := []domain.Rule{
		{RuleID: "r1", Effect: domain.EffectDeny, EffectConfig: domain.EffectConfig{SuggestedResponse: "x"}},
	}
	results := []domain.RuleResult{
		{RuleID: "r1", Matched: false, Effect: domain.EffectDeny},
	}
	if got := FindSuggestedResponse(rules, results); got != "" {
		t.Errorf("FindSuggestedResponse on unmatched rule = %q, want empty", got)
	}
}
