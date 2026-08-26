package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func auditEnv(id string) *domain.ActionEnvelope {
	return &domain.ActionEnvelope{
		EnvelopeID: id,
		OrgID:      "org-1",
		AgentID:    "agent-1",
		SessionID:  "sess-1",
		ToolName:   "bash",
		ToolGroup:  "shell",
	}
}

// hookAuditTraceOfSize builds a valid v2 record whose JSON representation is
// exactly target bytes. It lets the writer and verifier share one executable
// boundary contract instead of relying on approximate large-record fixtures.
func hookAuditTraceOfSize(t *testing.T, target int) *domain.DecisionTrace {
	return hookAuditTraceOfSizeWithPrevious(t, target, "")
}

func hookAuditTraceOfSizeWithPrevious(t *testing.T, target int, previousHash string) *domain.DecisionTrace {
	t.Helper()
	tr := &domain.DecisionTrace{
		CanonicalVersion:  audit.CanonicalTraceVersion,
		TraceID:           "trc-size-boundary",
		Timestamp:         time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		EnvelopeID:        "env-size-boundary",
		ToolName:          "bash",
		Decision:          domain.DecisionAllowed,
		ActionTaken:       domain.ActionAllowed,
		DecisionReason:    "x",
		PreviousTraceHash: previousHash,
	}

	marshalRehashed := func() []byte {
		tr.TraceHash = ""
		h, err := audit.ComputeCanonicalTraceHash(tr)
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
	if got := len(marshalRehashed()); got != target {
		t.Fatalf("sized trace length = %d, want %d", got, target)
	}
	return tr
}

// readChain returns each record's (prev, hash) in file order.
func readChain(t *testing.T, path string) [][2]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][2]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			CanonicalVersion string `json:"_canonical_v"`
			TraceHash        string `json:"trace_hash"`
			PrevHash         string `json:"previous_trace_hash"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		if rec.CanonicalVersion != audit.CanonicalTraceVersion {
			t.Errorf("audit canonical version = %q, want %q", rec.CanonicalVersion, audit.CanonicalTraceVersion)
		}
		out = append(out, [2]string{rec.PrevHash, rec.TraceHash})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAppendHookAudit_ChainLinks confirms sequential appends link
// previous_trace_hash → trace_hash with no gaps.
func TestAppendHookAudit_ChainLinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 5; i++ {
		if err := appendHookAudit(path, auditEnv("env"), nil, "allow", "ok"); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	chain := readChain(t, path)
	if len(chain) != 5 {
		t.Fatalf("want 5 records, got %d", len(chain))
	}
	if chain[0][0] != "" {
		t.Errorf("first record previous_trace_hash should be empty, got %q", chain[0][0])
	}
	for i := 1; i < len(chain); i++ {
		if chain[i][0] != chain[i-1][1] {
			t.Errorf("record %d prev %q != record %d hash %q — chain forked", i, chain[i][0], i-1, chain[i-1][1])
		}
	}
}

// TestAppendHookAudit_ConcurrentNoFork is the A1 regression: many hook
// processes appending at once must serialize under the lock and produce a
// single linear chain, never two records sharing the same previous hash.
func TestAppendHookAudit_ConcurrentNoFork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const n = 24
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// Ignore lock-contention give-ups; the ones that DID write must
			// still form a valid chain.
			_ = appendHookAudit(path, auditEnv("env"), nil, "allow", "ok")
		}()
	}
	wg.Wait()

	chain := readChain(t, path)
	if len(chain) == 0 {
		t.Fatal("no records written")
	}
	seenPrev := map[string]bool{}
	hashes := map[string]bool{}
	for i, rec := range chain {
		prev, hash := rec[0], rec[1]
		if i > 0 && seenPrev[prev] {
			t.Fatalf("record %d reuses previous_trace_hash %q — chain forked under concurrency", i, prev)
		}
		seenPrev[prev] = true
		if hashes[hash] {
			t.Fatalf("record %d has duplicate trace_hash %q", i, hash)
		}
		hashes[hash] = true
	}
	// Every non-genesis prev must be some earlier record's hash.
	for i, rec := range chain {
		if i == 0 {
			continue
		}
		if !hashes[rec[0]] {
			t.Errorf("record %d prev %q links to no known record", i, rec[0])
		}
	}
}

// TestLastTraceHash_TailReadDropsPartialLine is the A2 regression: when the
// last record starts before the 64KB tail window, lastTraceHash must skip the
// leading partial line and still return the correct final hash (never a
// garbage partial).
func TestLastTraceHash_TailReadDropsPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Write enough records that the earliest ones fall outside the 64KB tail.
	const n = 400
	for i := 0; i < n; i++ {
		if err := appendHookAudit(path, auditEnv("env"), nil, "allow", strings.Repeat("x", 300)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	chain := readChain(t, path)
	want := chain[len(chain)-1][1]

	got, err := lastTraceHash(path)
	if err != nil {
		t.Fatalf("lastTraceHash: %v", err)
	}
	if got != want {
		t.Errorf("lastTraceHash returned %q, want last record hash %q", got, want)
	}
}

func TestAppendHookAudit_LargeRecordKeepsNextLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	large := &domain.EvaluationResult{
		Decision:       domain.DecisionDenied,
		ActionTaken:    domain.ActionDenied,
		DecisionReason: strings.Repeat("large-provenance-", 5000),
		EffectiveMode:  domain.PolicyModeEnforcement,
	}
	if err := appendHookAudit(path, auditEnv("large"), large, "deny", "unused"); err != nil {
		t.Fatalf("append large record: %v", err)
	}
	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append next record: %v", err)
	}

	chain := readChain(t, path)
	if len(chain) != 2 {
		t.Fatalf("want 2 records, got %d", len(chain))
	}
	if chain[1][0] != chain[0][1] {
		t.Fatalf("large record forked chain: second prev %q, first hash %q", chain[1][0], chain[0][1])
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		t.Fatalf("verify large-record chain: %v", err)
	}
	if !report.Intact || report.Records != 2 {
		t.Fatalf("large-record chain verification = %#v, want intact with 2 records", report)
	}
}

func TestHookAudit_RecordSizeBoundary(t *testing.T) {
	exact := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(exact)
	if err != nil {
		t.Fatalf("marshal exact-max record: %v", err)
	}
	if len(line) != audit.MaxTraceRecordBytes {
		t.Fatalf("exact record length = %d, want %d", len(line), audit.MaxTraceRecordBytes)
	}

	tooLarge := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes+1)
	if _, err := audit.MarshalTraceRecord(tooLarge); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("marshal max+1 error = %v, want maximum-size error", err)
	}
}

func TestAppendHookAudit_ExtendsExactMaxRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(first)
	if err != nil {
		t.Fatalf("marshal exact-max record: %v", err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("write exact-max record: %v", err)
	}
	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append after exact-max record: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		t.Fatalf("verify exact-max chain: %v", err)
	}
	if !report.Intact || report.Records != 2 {
		t.Fatalf("exact-max chain verification = %#v, want intact with 2 records", report)
	}
}

func TestAppendHookAudit_ExtendsPriorPlusExactMaxCRLFRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	prior := hookAuditTraceOfSize(t, 1024)
	priorLine, err := audit.MarshalTraceRecord(prior)
	if err != nil {
		t.Fatalf("marshal prior record: %v", err)
	}
	exact := hookAuditTraceOfSizeWithPrevious(t, audit.MaxTraceRecordBytes, prior.TraceHash)
	exactLine, err := audit.MarshalTraceRecord(exact)
	if err != nil {
		t.Fatalf("marshal exact-max record: %v", err)
	}
	contents := append(append(append([]byte(nil), priorLine...), '\n'), exactLine...)
	contents = append(contents, '\r', '\n')
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write two-record chain: %v", err)
	}

	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append after prior + exact-max CRLF record: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact || report.Records != 3 {
		t.Fatalf("CRLF boundary chain = %#v, want intact with 3 records", report)
	}
}

func TestAppendHookAudit_RejectsVerifierOversizedWhitespaceRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	exact := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(exact)
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append(append([]byte(nil), line...), ' '), '\n')
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	before := int64(len(contents))

	err = appendHookAudit(path, auditEnv("next"), nil, "allow", "ok")
	if err == nil || !strings.Contains(err.Error(), "last record exceeds") {
		t.Fatalf("append error = %v, want verifier-size rejection", err)
	}
	st, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if st.Size() != before {
		t.Fatalf("rejected append changed file size from %d to %d", before, st.Size())
	}
}

func TestAppendHookAudit_RejectsWhitespaceOnlyTrailingRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := appendHookAudit(path, auditEnv("first"), nil, "allow", "ok"); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" \n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	err = appendHookAudit(path, auditEnv("next"), nil, "allow", "ok")
	if err == nil || !strings.Contains(err.Error(), "whitespace-only trailing record") {
		t.Fatalf("append error = %v, want whitespace-only-tail rejection", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("rejected append changed file size from %d to %d", before.Size(), after.Size())
	}
}

func TestAppendHookAuditBestEffort_ReportsOversizedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	result := &domain.EvaluationResult{
		Decision:          domain.DecisionDenied,
		ActionTaken:       domain.ActionDenied,
		EffectiveMode:     domain.PolicyModeEnforcement,
		SuggestedResponse: strings.Repeat("x", audit.MaxTraceRecordBytes),
	}
	var stderr bytes.Buffer
	appendHookAuditBestEffort(&stderr, path, auditEnv("oversized"), result, "deny", "unused")

	if got := stderr.String(); !strings.Contains(got, "audit append failed") || !strings.Contains(got, "record not written") {
		t.Fatalf("stderr = %q, want surfaced audit-loss warning", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("oversized record created audit file; stat error = %v", err)
	}
}
