package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestNeedsRecordSeparator(t *testing.T) {
	for _, tt := range []struct {
		name     string
		contents string
		want     bool
	}{
		{name: "empty", contents: "", want: false},
		{name: "lf terminated", contents: "{}\n", want: false},
		{name: "crlf terminated", contents: "{}\r\n", want: false},
		{name: "eof terminated", contents: "{}", want: true},
		{name: "bare cr becomes crlf", contents: "{}\r", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, []byte(tt.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := NeedsRecordSeparator(f)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("NeedsRecordSeparator() = %v, want %v", got, tt.want)
			}
		})
	}
}

// traceJSONOfSize builds a valid trace whose encoded JSON is exactly target
// bytes. A single-byte padding alphabet keeps the size adjustment linear.
func traceJSONOfSize(t *testing.T, target int) []byte {
	t.Helper()
	tr := makeTrace("size-boundary", "env-size-boundary", "", time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	tr.DecisionReason = "x"

	marshalRehashed := func() []byte {
		tr.TraceHash = ""
		h, err := ComputeCanonicalTraceHash(&tr)
		if err != nil {
			t.Fatalf("canonical hash: %v", err)
		}
		tr.TraceHash = h
		b, err := json.Marshal(tr)
		if err != nil {
			t.Fatalf("marshal trace: %v", err)
		}
		return b
	}

	base := marshalRehashed()
	if target < len(base) {
		t.Fatalf("target %d is smaller than base trace %d", target, len(base))
	}
	tr.DecisionReason += strings.Repeat("x", target-len(base))
	got := marshalRehashed()
	if len(got) != target {
		t.Fatalf("sized trace length = %d, want %d", len(got), target)
	}
	return got
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

// A 0.7 writer emits markerless canonical-v1 records. Once any v2 record has
// appeared, accepting a later markerless record would let an old writer
// silently weaken the integrity commitment while preserving valid hashes and
// links. Physical append is possible; valid chain resumption is not.
func TestVerifyChainFromReader_RejectsV070WriterAfterV2(t *testing.T) {
	fixture, err := os.ReadFile("testdata/v2-then-v070-hook.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyChainFromReader(bytes.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact || rep.FirstFailureAt != 2 || !strings.Contains(rep.FailureReason, "canonical version downgrade from v2 to v1") {
		t.Fatalf("downgrade report = %#v, want canonical-version failure at line 2", rep)
	}
}

func TestVerifyChainFromReader_RejectsDetachedSuffix(t *testing.T) {
	fixture, err := os.ReadFile("testdata/v2-then-v070-hook.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(fixture), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("fixture lines = %d, want 2", len(lines))
	}
	rep, err := VerifyChainFromReader(bytes.NewReader(append(lines[1], '\n')))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact || rep.FirstFailureAt != 1 || !strings.Contains(rep.FailureReason, "genesis previous_trace_hash") {
		t.Fatalf("detached-suffix report = %#v, want genesis failure at line 1", rep)
	}
}

func TestVerifyChainFromReader_RejectsV2OnlyAmountStatusOnV1(t *testing.T) {
	trace := makeTrace("v1-status-injection", "env-v1-status", "", time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC))
	// Simulate an attacker changing a display field after the markerless v1
	// hash was computed. V1 cannot claim this v2 provenance because its
	// historical canonical projection never committed to the field.
	trace.AmountParseStatus = "invalid_fail_closed"
	report, err := VerifyChainFromReader(bytes.NewReader(writeJSONL(t, []domain.DecisionTrace{trace})))
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact || report.FirstFailureAt != 1 || !strings.Contains(report.FailureReason, "v2-only provenance fields") {
		t.Fatalf("v1 amount-status injection report = %#v, want canonical failure at line 1", report)
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

func TestVerifyChainFromReader_RecordSizeBoundary(t *testing.T) {
	exact := traceJSONOfSize(t, MaxTraceRecordBytes)
	var exactTrace domain.DecisionTrace
	if err := json.Unmarshal(exact, &exactTrace); err != nil {
		t.Fatalf("decode exact-max trace: %v", err)
	}
	encoded, err := MarshalTraceRecord(&exactTrace)
	if err != nil {
		t.Fatalf("MarshalTraceRecord exact max: %v", err)
	}
	if len(encoded) != MaxTraceRecordBytes {
		t.Fatalf("MarshalTraceRecord length = %d, want %d", len(encoded), MaxTraceRecordBytes)
	}
	for _, tc := range []struct {
		name      string
		delimiter string
	}{
		{name: "LF", delimiter: "\n"},
		{name: "CRLF", delimiter: "\r\n"},
		{name: "EOF", delimiter: ""},
	} {
		t.Run("accept exact max with "+tc.name, func(t *testing.T) {
			input := append(append([]byte(nil), exact...), tc.delimiter...)
			rep, err := VerifyChainFromReader(bytes.NewReader(input))
			if err != nil {
				t.Fatalf("VerifyChainFromReader: %v", err)
			}
			if !rep.Intact || rep.Records != 1 {
				t.Fatalf("exact-max report = %#v, want intact one-record chain", rep)
			}
		})
	}

	tooLarge := traceJSONOfSize(t, MaxTraceRecordBytes+1)
	var tooLargeTrace domain.DecisionTrace
	if err := json.Unmarshal(tooLarge, &tooLargeTrace); err != nil {
		t.Fatalf("decode max+1 trace: %v", err)
	}
	if _, err := MarshalTraceRecord(&tooLargeTrace); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("MarshalTraceRecord max+1 error = %v, want maximum-size error", err)
	}

	rep, err := VerifyChainFromReader(bytes.NewReader(append(tooLarge, '\n')))
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if rep.Intact || rep.FirstFailureAt != 1 || !strings.Contains(rep.FailureReason, "record exceeds") {
		t.Fatalf("max+1 report = %#v, want a record-size failure at line 1", rep)
	}
}
