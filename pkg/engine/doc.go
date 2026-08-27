// Package engine is the deterministic policy-evaluation core of Tool Guard.
//
// Given an [github.com/dimaggi-ai/tool-guard-core/pkg/domain.ActionEnvelope]
// and a slice of [github.com/dimaggi-ai/tool-guard-core/pkg/domain.Policy],
// the [Evaluator] returns a [github.com/dimaggi-ai/tool-guard-core/pkg/domain.EvaluationResult]
// describing whether the tool call should be allowed, denied, escalated,
// or flagged — and which rules and citations drove the decision.
//
// Evaluator is safe to call from any number of goroutines concurrently.
// Deterministic conditions perform no I/O. Policies that use llm_classify are
// the explicit exception: they call the configured model endpoint and may
// fetch an image URL through the SSRF-hardened client.
//
// The package keeps process-wide, concurrency-safe implementation state:
// bounded classifier-client and compiled-regex caches, a shared image fetcher,
// and the optional hook configured through [SetLLMClassifyHook]. The hook
// affects every Evaluator in the process, so configure it during initialization
// or in tests that restore the previous value. A typical embed:
//
//	eval := engine.NewEvaluator()
//	result := eval.Evaluate(envelope, policies, domain.PolicyModeEnforcement)
//	if result.ActionTaken == domain.ActionDenied {
//	    // block the tool call; record result.AppliedPrimaryCitation in your audit
//	}
//
// Use [github.com/dimaggi-ai/tool-guard-core/pkg/audit] to hash-chain the
// resulting traces, and the `tg` CLI (under cmd/tg) for policy tooling and
// offline audit workflows.
package engine
