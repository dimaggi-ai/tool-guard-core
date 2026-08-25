package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// makeTrace builds one valid trace whose TraceHash matches the canonical
// recomputation. Tests use it to construct intact or tampered chains.
func makeTrace(traceID, envelopeID, prevHash string, ts time.Time) domain.DecisionTrace {
	tr := domain.DecisionTrace{
		TraceID:           traceID,
		EnvelopeID:        envelopeID,
		Timestamp:         ts,
		Decision:          domain.DecisionAllowed,
		ActionTaken:       domain.ActionAllowed,
		PreviousTraceHash: prevHash,
	}
	h, err := ComputeCanonicalTraceHash(&tr)
	if err != nil {
		panic("makeTrace: " + err.Error())
	}
	tr.TraceHash = h
	return tr
}

func writeJSONL(t *testing.T, traces []domain.DecisionTrace) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, tr := range traces {
		b, err := json.Marshal(tr)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func TestVerifyChainFromReader_IntactChain(t *testing.T) {
	ts := time.Now().Truncate(time.Microsecond)
	t1 := makeTrace("t1", "env-1", "", ts)
	t2 := makeTrace("t2", "env-2", t1.TraceHash, ts.Add(time.Second))
	t3 := makeTrace("t3", "env-3", t2.TraceHash, ts.Add(2*time.Second))

	rep, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, []domain.DecisionTrace{t1, t2, t3})))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if !rep.Intact {
		t.Fatalf("Intact = false, want true: %+v", rep)
	}
	if rep.Records != 3 {
		t.Errorf("Records = %d, want 3", rep.Records)
	}
	if rep.Tail != t3.TraceHash {
		t.Errorf("Tail = %q, want %q", rep.Tail, t3.TraceHash)
	}
	if rep.FirstTraceID != "t1" {
		t.Errorf("FirstTraceID = %q, want t1", rep.FirstTraceID)
	}
}

func TestVerifyChainFromReader_MixedV1V2UpgradeChain(t *testing.T) {
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	v1 := makeTrace("v1", "env-v1", "", base)
	v2 := makeTrace("v2", "env-v2", v1.TraceHash, base.Add(time.Second))
	v2.CanonicalVersion = CanonicalTraceVersion
	v2.AppliedRuleResults = []domain.RuleResult{{
		RuleID:   "r2",
		PolicyID: "p2",
		Matched:  true,
		Effect:   domain.EffectDeny,
		Citation: domain.Citation{DocumentID: "doc", Excerpt: "applied"},
	}}
	citation := v2.AppliedRuleResults[0].Citation
	v2.AppliedPrimaryCitation = &citation
	hash, err := ComputeCanonicalTraceHash(&v2)
	if err != nil {
		t.Fatal(err)
	}
	v2.TraceHash = hash

	rep, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, []domain.DecisionTrace{v1, v2})))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Intact || rep.Records != 2 || rep.Tail != v2.TraceHash {
		t.Fatalf("mixed-version chain report = %#v, want intact 2-record chain", rep)
	}
}

func TestVerifyChainFromReader_TamperedHash(t *testing.T) {
	ts := time.Now().Truncate(time.Microsecond)
	t1 := makeTrace("t1", "env-1", "", ts)
	t2 := makeTrace("t2", "env-2", t1.TraceHash, ts.Add(time.Second))

	// Flip one byte of t2.TraceHash → canonical recomputation must catch it.
	t2.TraceHash = strings.Replace(t2.TraceHash, t2.TraceHash[len(t2.TraceHash)-1:], "x", 1)

	rep, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, []domain.DecisionTrace{t1, t2})))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if rep.Intact {
		t.Fatalf("Intact = true, want false on tampered hash")
	}
	if rep.FirstFailureAt != 2 {
		t.Errorf("FirstFailureAt = %d, want 2", rep.FirstFailureAt)
	}
	if !strings.Contains(rep.FailureReason, "trace_hash") {
		t.Errorf("FailureReason = %q, want it to mention trace_hash", rep.FailureReason)
	}
}

func TestVerifyChainFromReader_BrokenLink(t *testing.T) {
	ts := time.Now().Truncate(time.Microsecond)
	t1 := makeTrace("t1", "env-1", "", ts)
	t2 := makeTrace("t2", "env-2", "sha256:wronglink", ts.Add(time.Second))

	rep, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, []domain.DecisionTrace{t1, t2})))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if rep.Intact {
		t.Fatalf("Intact = true, want false on broken link")
	}
	if rep.FirstFailureAt != 2 {
		t.Errorf("FirstFailureAt = %d, want 2", rep.FirstFailureAt)
	}
	if !strings.Contains(rep.FailureReason, "previous_trace_hash") {
		t.Errorf("FailureReason = %q, want it to mention previous_trace_hash", rep.FailureReason)
	}
}

func TestVerifyChainFromReader_MalformedJSON(t *testing.T) {
	junk := []byte("t1, this is not JSON\n")
	rep, err := VerifyChainFromReader(bytes.NewReader(junk))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if rep.Intact {
		t.Fatalf("Intact = true, want false on malformed JSON")
	}
	if rep.FirstFailureAt != 1 {
		t.Errorf("FirstFailureAt = %d, want 1", rep.FirstFailureAt)
	}
}

func TestVerifyChainFromReader_EmptyStream(t *testing.T) {
	rep, err := VerifyChainFromReader(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if !rep.Intact {
		t.Fatalf("Intact = false on empty stream; want true (vacuously)")
	}
	if rep.Records != 0 {
		t.Errorf("Records = %d, want 0", rep.Records)
	}
}
