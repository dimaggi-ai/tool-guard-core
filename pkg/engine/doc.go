// Package engine is the deterministic policy-evaluation core of Tool Guard.
//
// Given an [github.com/dimaggi-ai/tool-guard-core/pkg/domain.ActionEnvelope]
// and a slice of [github.com/dimaggi-ai/tool-guard-core/pkg/domain.Policy],
// the [Evaluator] returns a [github.com/dimaggi-ai/tool-guard-core/pkg/domain.EvaluationResult]
// describing whether the tool call should be allowed, denied, escalated,
// or flagged — and which rules and citations drove the decision.
//
// The engine has zero I/O, zero external dependencies, and is safe to call
// from any number of goroutines concurrently: there are no package-level
// caches, mutexes, or shared state. A typical embed:
//
//	eval := engine.NewEvaluator()
//	result := eval.Evaluate(envelope, policies, domain.PolicyModeEnforcement)
//	if result.Decision == domain.DecisionDenied {
//	    // block the tool call; record result.PrimaryCitation in your audit
//	}
//
// Use [github.com/dimaggi-ai/tool-guard-core/pkg/audit] to hash-chain the
// resulting traces, and the `tg` CLI (under cmd/tg) for the offline
// verify / lint / benchmark workflow.
package engine
