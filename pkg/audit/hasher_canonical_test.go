package audit

import (
	"math"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestAmountCentsCanonical_FiniteSymmetric verifies that the cents
// rounding is symmetric on negative values (the previous +0.5 trick
// was not — -1.5 became -1 instead of -2) and that math.Round handles
// the half-away-from-zero rule correctly.
func TestAmountCentsCanonical_FiniteSymmetric(t *testing.T) {
	// We test exact-representable values; 1.005 etc. aren't exact in
	// float64, so the test would assert on FP imprecision rather than
	// the function's rounding semantic.
	cases := map[float64]int64{
		0.0:       0,
		1.00:      100,
		1.50:      150, // half-away-from-zero
		-1.00:     -100,
		-1.50:     -150, // symmetric (the previous +0.5 produced -149)
		0.999:     100,  // rounds up
		-0.999:    -100,
		1_000_000: 100_000_000,
	}
	for amount, want := range cases {
		got := amountCentsCanonical(amount)
		if got != want {
			t.Errorf("amountCentsCanonical(%v) = %d, want %d", amount, got, want)
		}
	}
}

// TestAmountCentsCanonical_NonFiniteDistinct verifies NaN, +Inf, -Inf
// each serialise to a DIFFERENT int64 — collapsing them onto the same
// canonical bytes would let adversary-distinct floats produce
// byte-identical audit entries.
func TestAmountCentsCanonical_NonFiniteDistinct(t *testing.T) {
	nan := amountCentsCanonical(math.NaN())
	posInf := amountCentsCanonical(math.Inf(1))
	negInf := amountCentsCanonical(math.Inf(-1))
	if nan == posInf || nan == negInf || posInf == negInf {
		t.Errorf("non-finite specials must map to distinct ints: NaN=%d +Inf=%d -Inf=%d",
			nan, posInf, negInf)
	}
	if posInf != math.MaxInt64 {
		t.Errorf("+Inf should map to MaxInt64, got %d", posInf)
	}
	if negInf != math.MinInt64 {
		t.Errorf("-Inf should map to MinInt64, got %d", negInf)
	}
}

// TestComputeCanonicalTraceHash_NilTrace covers the nil-input
// defensive return.
func TestComputeCanonicalTraceHash_NilTrace(t *testing.T) {
	if _, err := ComputeCanonicalTraceHash(nil); err == nil {
		t.Errorf("ComputeCanonicalTraceHash(nil) should error")
	}
}

// TestComputeCanonicalTraceHash_DeterministicForSameTrace asserts the
// hasher produces byte-identical output for the same trace called
// twice — saved.TraceHash round-trip must not perturb the result.
func TestComputeCanonicalTraceHash_Deterministic(t *testing.T) {
	tr := &domain.DecisionTrace{
		TraceID:        "trc-1",
		EnvelopeID:     "env-1",
		Timestamp:      time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
		Decision:       domain.DecisionAllowed,
		ActionTaken:    domain.ActionAllowed,
		DecisionReason: "ok",
		Amount:         1234.56,
	}
	h1, err := ComputeCanonicalTraceHash(tr)
	if err != nil {
		t.Fatalf("hash 1: %v", err)
	}
	tr.TraceHash = "intermediate-value-from-storage"
	h2, err := ComputeCanonicalTraceHash(tr)
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic across calls: %s != %s", h1, h2)
	}
}

// TestVerifyCanonicalTraceHash covers the round-trip verification
// helper.
func TestVerifyCanonicalTraceHash(t *testing.T) {
	tr := &domain.DecisionTrace{
		TraceID:     "trc-verify",
		EnvelopeID:  "env-verify",
		Timestamp:   time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
		Decision:    domain.DecisionDenied,
		ActionTaken: domain.ActionDenied,
		Amount:      999.99,
	}
	h, err := ComputeCanonicalTraceHash(tr)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	tr.TraceHash = h
	ok, err := VerifyCanonicalTraceHash(tr)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Errorf("verify should succeed on a fresh canonical hash")
	}
	// Mutate decision_reason and confirm verification fails.
	tr.DecisionReason = "tampered after the fact"
	ok, err = VerifyCanonicalTraceHash(tr)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if ok {
		t.Errorf("verify must FAIL after decision_reason tamper")
	}
	// Nil trace returns error.
	if _, err := VerifyCanonicalTraceHash(nil); err == nil {
		t.Errorf("VerifyCanonicalTraceHash(nil) should error")
	}
}
