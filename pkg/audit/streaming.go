package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// StreamReport is the result of a streaming chain verification.
//
// Intact is true only if every line parses, hashes match the canonical
// recomputation, and every PreviousTraceHash links to the prior record's
// TraceHash. Tail is the last verified TraceHash — handed to the caller
// so they can pin "the chain as I saw it ended here" elsewhere (e.g. an
// evidence pack manifest).
type StreamReport struct {
	Intact         bool   `json:"intact"`
	Records        int    `json:"records"`
	FirstTraceID   string `json:"first_trace_id,omitempty"`
	Tail           string `json:"tail_hash,omitempty"`
	FirstFailureAt int    `json:"first_failure_at,omitempty"` // 1-indexed line number
	FailureReason  string `json:"failure_reason,omitempty"`
	Note           string `json:"note,omitempty"` // free-form info, e.g. rotation files walked
}

// VerifyChainFromReader replays a JSONL stream of decision traces and
// reports whether the chain is tamper-free. One round-trip — no DB, no
// network, no Tool Guard infrastructure. This is the primitive an
// auditor's offline `tg verify -file decisions.jsonl` runs on.
//
// Verification rules:
//   - Each line must be a valid JSON DecisionTrace.
//   - For line N>1, trace.PreviousTraceHash must equal line N-1's TraceHash.
//   - trace.TraceHash must equal ComputeCanonicalTraceHash(...) with the canonical
//     fields of this record.
//
// On the first violation the report's Intact is false, FirstFailureAt
// pins the line, and FailureReason explains why. The function still
// returns nil; callers check report.Intact.
func VerifyChainFromReader(r io.Reader) (*StreamReport, error) {
	sc := bufio.NewScanner(r)
	// Decision traces can be large (rule_results + context_snapshot); raise
	// the scanner's per-line ceiling so big-but-valid records are not
	// silently truncated. 4 MiB is comfortably above a realistic trace.
	buf := make([]byte, 0, 1<<20)
	sc.Buffer(buf, 4*1024*1024)

	rep := &StreamReport{Intact: true}
	var prevHash string
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}

		var t domain.DecisionTrace
		if err := json.Unmarshal(raw, &t); err != nil {
			return failAt(rep, line, fmt.Sprintf("parse JSON: %v", err)), nil
		}

		if rep.Records == 0 {
			rep.FirstTraceID = t.TraceID
		} else if t.PreviousTraceHash != prevHash {
			return failAt(rep, line, fmt.Sprintf("previous_trace_hash %q does not match prior tail %q", t.PreviousTraceHash, prevHash)), nil
		}

		// Recompute the canonical hash over the WHOLE trace (rule
		// results, decision_reason, agent identity, amount). No
		// legacy-hash fallback: a 6-field hash covers only identity
		// + decision, so an attacker who knows the verifier accepts
		// legacy could forge decision_reason / rule_results /
		// amount / mode while keeping a legacy match. Single-path
		// canonical hashing is the integrity commitment.
		want, err := ComputeCanonicalTraceHash(&t)
		if err != nil {
			return failAt(rep, line, fmt.Sprintf("canonical recompute: %v", err)), nil
		}
		if t.TraceHash != want {
			return failAt(rep, line, fmt.Sprintf("trace_hash %q does not match canonical recomputation %q", t.TraceHash, want)), nil
		}

		prevHash = t.TraceHash
		rep.Records++
	}
	if err := sc.Err(); err != nil {
		return failAt(rep, line, fmt.Sprintf("scan: %v", err)), nil
	}
	rep.Tail = prevHash
	return rep, nil
}

func failAt(rep *StreamReport, line int, reason string) *StreamReport {
	rep.Intact = false
	rep.FirstFailureAt = line
	rep.FailureReason = reason
	return rep
}
