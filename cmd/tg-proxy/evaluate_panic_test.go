package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestRecoverEvaluation_NormalReturn proves the wrapper is a no-op pass-
// through on the common path: same result, nil error.
func TestRecoverEvaluation_NormalReturn(t *testing.T) {
	want := &domain.EvaluationResult{Decision: domain.DecisionAllowed}
	got, err := recoverEvaluation(func() *domain.EvaluationResult { return want })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("result = %v, want the same pointer returned by fn", got)
	}
}

// TestRecoverEvaluation_Panic is the core guarantee this change adds: a
// panic inside fn must come back as (nil, error), never propagate. Before
// this fix there was no recover() around the evaluator call at all — a
// panic used to unwind out of the HTTP handler into net/http's own per-
// connection recover, which just drops the connection with no decision, no
// audit trace, and no counter increment. See safeEvaluate's doc comment in
// handlers.go for the full reasoning.
func TestRecoverEvaluation_Panic(t *testing.T) {
	result, err := recoverEvaluation(func() *domain.EvaluationResult {
		panic("simulated engine panic (e.g. a nil-pointer bug in a condition leaf)")
	})
	if result != nil {
		t.Fatalf("result = %v, want nil after a recovered panic", result)
	}
	if err == nil {
		t.Fatal("err = nil, want a non-nil error describing the panic")
	}
	if !strings.Contains(err.Error(), "simulated engine panic") {
		t.Fatalf("err = %q, want it to carry the panic value", err.Error())
	}
}

// TestRecoverEvaluation_PanicWithNonStringValue proves recover() also
// handles a panic(err) or panic(anyValue) — Go code sometimes panics with a
// non-string value — without the recover handler itself crashing on a bad
// type assertion. fmt.Errorf("%v", r) must handle any panic value.
func TestRecoverEvaluation_PanicWithNonStringValue(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := recoverEvaluation(func() *domain.EvaluationResult {
		panic(sentinel)
	})
	if err == nil {
		t.Fatal("err = nil, want a non-nil error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %q, want it to carry the panic value %q", err.Error(), sentinel.Error())
	}
}

// TestRecoverEvaluation_NilPointerDereference exercises recover() against a
// REAL nil-pointer panic (not a manufactured panic() call) — the actual
// class of bug this is meant to catch — to prove the recover mechanism
// works against Go's own runtime panics, not just explicit panic() calls.
func TestRecoverEvaluation_NilPointerDereference(t *testing.T) {
	var boom *domain.EvaluationResult
	_, err := recoverEvaluation(func() *domain.EvaluationResult {
		return &domain.EvaluationResult{Decision: boom.Decision} // nil deref
	})
	if err == nil {
		t.Fatal("err = nil, want a non-nil error from the nil-pointer dereference")
	}
}
