package engine

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestStress_ConcurrentEvaluate hammers a single shared *Evaluator from many
// goroutines. The /evaluate service serves concurrent requests off one
// evaluator and one shared policy set, so Evaluate must be safe for concurrent
// use and fully deterministic: identical input -> identical decision, every
// time. The deny / escalate / allow cases each have one unambiguous expected
// Decision (the rule verdict is independent of shadow vs enforcement), so any
// mismatch means a data race corrupted a result. A regex rule that never
// matches is included so every evaluation also touches the package-level regex
// cache (sync.Map) — run under `make test` (-race) this flags cache races too.
func TestStress_ConcurrentEvaluate(t *testing.T) {
	eval := NewEvaluator()

	policy := makePolicy([]domain.Rule{
		{
			RuleID:     "deny-high",
			Name:       "deny-high",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(1000)},
			Effect:     domain.EffectDeny,
			Citation:   domain.Citation{Excerpt: "hard cap"},
		},
		{
			RuleID:     "escalate-mid",
			Name:       "escalate-mid",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
			Effect:     domain.EffectEscalate,
			Citation:   domain.Citation{Excerpt: "soft cap"},
		},
		{
			RuleID:     "regex-probe",
			Name:       "regex-probe",
			Conditions: domain.Condition{Field: "tool_name", Operator: domain.OpRegex, Value: "^DROP_"},
			Effect:     domain.EffectFlag,
			Citation:   domain.Citation{Excerpt: "never matches issue_refund — exercises the regex cache"},
		},
	})
	policies := []domain.Policy{policy}

	cases := []struct {
		amount float64
		want   domain.Decision
	}{
		{200, domain.DecisionAllowed},   // no rule fires
		{800, domain.DecisionEscalated}, // > 500 only
		{1500, domain.DecisionDenied},   // > 1000 (deny outranks escalate)
	}

	workers := runtime.GOMAXPROCS(0) * 4
	if workers < 8 {
		workers = 8
	}
	iters := 2000
	if testing.Short() {
		iters = 200
	}

	var mismatches int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			// Each goroutine owns its envelopes (a request builds its own);
			// the evaluator and policy slice are the shared, read-only state.
			envs := make([]*domain.ActionEnvelope, len(cases))
			for i, c := range cases {
				envs[i] = makeEnvelope(c.amount, "issue_refund", "agent-stress", "org-stress")
			}
			for i := 0; i < iters; i++ {
				idx := (seed + i) % len(cases)
				res := eval.Evaluate(envs[idx], policies, domain.PolicyModeEnforcement)
				if res.Decision != cases[idx].want {
					atomic.AddInt64(&mismatches, 1)
				}
			}
		}(w)
	}
	wg.Wait()

	if mismatches != 0 {
		t.Fatalf("concurrent Evaluate produced %d wrong decisions across %d workers — non-deterministic or unsafe for concurrent use",
			mismatches, workers)
	}
}
