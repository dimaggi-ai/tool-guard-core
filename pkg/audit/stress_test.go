package audit

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// buildChain returns n linked, valid traces and their JSONL encoding. Each
// record's PreviousTraceHash is the prior record's canonical TraceHash, so the
// whole stream verifies intact.
func buildChain(t *testing.T, n int) ([]domain.DecisionTrace, []byte) {
	t.Helper()
	ts := time.Now().Truncate(time.Microsecond)
	traces := make([]domain.DecisionTrace, n)
	prev := ""
	for i := 0; i < n; i++ {
		tr := makeTrace(fmt.Sprintf("t%d", i+1), fmt.Sprintf("env-%d", i+1), prev,
			ts.Add(time.Duration(i)*time.Millisecond))
		traces[i] = tr
		prev = tr.TraceHash
	}
	return traces, writeJSONL(t, traces)
}

// TestStress_AuditChainAtScale verifies that the offline chain verifier stays
// correct on a long ledger, still pinpoints a single tampered record buried
// deep in the chain, and is a pure function safe to run concurrently.
func TestStress_AuditChainAtScale(t *testing.T) {
	n := 20_000
	if testing.Short() {
		n = 2_000
	}
	traces, jsonl := buildChain(t, n)

	t.Run("intact_at_scale", func(t *testing.T) {
		rep, err := VerifyChainFromReader(bytes.NewReader(jsonl))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !rep.Intact {
			t.Fatalf("Intact=false on a clean %d-record chain: failure at %d (%s)",
				n, rep.FirstFailureAt, rep.FailureReason)
		}
		if rep.Records != n {
			t.Errorf("Records=%d, want %d", rep.Records, n)
		}
		if rep.Tail != traces[n-1].TraceHash {
			t.Errorf("Tail=%q, want %q", rep.Tail, traces[n-1].TraceHash)
		}
	})

	t.Run("tamper_deep_in_chain", func(t *testing.T) {
		mid := n / 2
		tampered := make([]domain.DecisionTrace, n)
		copy(tampered, traces)
		// Mutate a hashed field without recomputing the hash — the canonical
		// recomputation must catch it exactly at that line.
		tampered[mid].Decision = domain.DecisionDenied
		rep, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, tampered)))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if rep.Intact {
			t.Fatal("Intact=true on a tampered record; want false")
		}
		if rep.FirstFailureAt != mid+1 { // line numbers are 1-indexed
			t.Errorf("FirstFailureAt=%d, want %d", rep.FirstFailureAt, mid+1)
		}
	})

	t.Run("concurrent_verify_agrees", func(t *testing.T) {
		// A smaller chain hammered by many verifiers — VerifyChainFromReader
		// must be pure: every goroutine reads its own bytes.Reader and must
		// reach the same verdict.
		_, small := buildChain(t, 2_000)
		const goroutines = 24
		var disagreements int64
		var wg sync.WaitGroup
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rep, err := VerifyChainFromReader(bytes.NewReader(small))
				if err != nil || !rep.Intact || rep.Records != 2_000 {
					atomic.AddInt64(&disagreements, 1)
				}
			}()
		}
		wg.Wait()
		if disagreements != 0 {
			t.Fatalf("%d/%d concurrent verifications disagreed — verify is not pure",
				disagreements, goroutines)
		}
	})
}
