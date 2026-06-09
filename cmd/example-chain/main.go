// example-chain generates a sample SHA-256 hash-chained decision log
// that `tg verify` can read. It exists so the published example file
// at examples/decisions_chain.jsonl is reproducible (re-run this tool
// after CanonicalTraceVersion bumps or schema additions).
//
//	# regenerate the example chain
//	go run ./cmd/example-chain > examples/decisions_chain.jsonl
//
// The chain models a small support session: a $50 refund (allowed) → a
// $1000 refund (denied) → a $200 refund (allowed). Timestamps are
// rolled back to a fixed instant so the file is byte-stable across
// runs.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func main() {
	// Fixed timestamp so the chain is reproducible. UTC because the
	// canonical hasher normalises before hashing anyway.
	base := time.Date(2026, time.January, 15, 9, 30, 0, 0, time.UTC)

	traces := []domain.DecisionTrace{
		mkTrace("trc-0001", "env-0001", "", base.Add(0*time.Second),
			domain.DecisionAllowed, domain.ActionAllowed),
		mkTrace("trc-0002", "env-0002", "", base.Add(12*time.Second),
			domain.DecisionDenied, domain.ActionDenied),
		mkTrace("trc-0003", "env-0003", "", base.Add(47*time.Second),
			domain.DecisionAllowed, domain.ActionAllowed),
	}
	chain(traces)

	enc := json.NewEncoder(os.Stdout)
	for _, t := range traces {
		if err := enc.Encode(t); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
	}
}

func mkTrace(traceID, envelopeID, prev string, ts time.Time, d domain.Decision, a domain.ActionTaken) domain.DecisionTrace {
	return domain.DecisionTrace{
		TraceID:           traceID,
		EnvelopeID:        envelopeID,
		Timestamp:         ts,
		Decision:          d,
		ActionTaken:       a,
		PreviousTraceHash: prev,
	}
}

// chain walks the slice in order, filling in each PreviousTraceHash
// from the prior record's TraceHash and stamping each record's
// TraceHash with the canonical hasher (covers the whole trace, not
// just the 6-field identity tuple). After this returns, the slice is
// a valid chain that `tg verify` will report as intact, and mutating
// any field of any record (decision_reason, rule_results, agent_id,
// amount, etc.) will break verification.
func chain(traces []domain.DecisionTrace) {
	var prev string
	for i := range traces {
		traces[i].PreviousTraceHash = prev
		h, err := audit.ComputeCanonicalTraceHash(&traces[i])
		if err != nil {
			panic(fmt.Sprintf("canonical hash trace %d: %v", i, err))
		}
		traces[i].TraceHash = h
		prev = traces[i].TraceHash
	}
}
