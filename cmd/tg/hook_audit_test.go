package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
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
		TraceID:           "trc-size-boundary",
		Timestamp:         time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		EnvelopeID:        "env-size-boundary",
		ToolName:          "bash",
		Decision:          domain.DecisionAllowed,
		ActionTaken:       domain.ActionAllowed,
		DecisionReason:    "x",
		PreviousTraceHash: previousHash,
	}
	if err := audit.StampProvenance(tr, "v0.8.0-test", "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
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

func TestAppendHookAudit_StampsVerifiableProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := appendHookAudit(path, auditEnv("env-provenance"), nil, "deny", "blocked"); err != nil {
		t.Fatalf("appendHookAudit: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var trace domain.DecisionTrace
	if err := json.Unmarshal(bytes.TrimSpace(raw), &trace); err != nil {
		t.Fatalf("decode audit record: %v", err)
	}
	wantPolicyHash, err := policyload.PolicySetHash(nil)
	if err != nil {
		t.Fatalf("hash empty policy set: %v", err)
	}
	if trace.EngineVersion == "" || trace.PolicySetHash != wantPolicyHash || trace.SchemaVersion != audit.CanonicalTraceVersion {
		t.Fatalf("incomplete provenance: %+v", trace)
	}
	ok, err := audit.VerifyCanonicalTraceHash(&trace)
	if err != nil {
		t.Fatalf("VerifyCanonicalTraceHash: %v", err)
	}
	if !ok {
		t.Fatal("fresh hook audit record did not verify")
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

func TestAcquireAuditLock_LiveHolderWithOldMtimeCannotBeStolen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	unlock, err := acquireAuditLock(path)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()

	// Reproduce the old failure without a 10-second sleep: an age-based lock
	// implementation would treat this live holder as stale and unlink it.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path+".lock", old, old); err != nil {
		t.Fatalf("age live lockfile: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAcquireAuditLock_ContenderProcess$")
	cmd.Env = append(os.Environ(), "TG_TEST_AUDIT_LOCK_PATH="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("contender process: %v\n%s", err, output)
	}

	unlock()
	released = true
	nextUnlock, err := acquireAuditLock(path)
	if err != nil {
		t.Fatalf("acquire after live holder released: %v", err)
	}
	nextUnlock()
}

func TestAcquireAuditLock_ContenderProcess(t *testing.T) {
	path := os.Getenv("TG_TEST_AUDIT_LOCK_PATH")
	if path == "" {
		t.Skip("helper process only")
	}
	unlock, err := acquireAuditLock(path)
	if err == nil {
		unlock()
		t.Fatal("acquired a lock still held by the parent process")
	}
	if !strings.Contains(err.Error(), "could not acquire lock") {
		t.Fatalf("unexpected contention error: %v", err)
	}
}

func TestAcquireAuditLock_HolderExitReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestAcquireAuditLock_ExitHolderProcess$")
	cmd.Env = append(os.Environ(), "TG_TEST_AUDIT_LOCK_EXIT_PATH="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("holder process: %v\n%s", err, output)
	}

	// The helper deliberately exits without calling its unlock closure. The OS
	// must release the advisory lock even though the persistent lockfile remains.
	unlock, err := acquireAuditLock(path)
	if err != nil {
		t.Fatalf("acquire after holder process exit: %v", err)
	}
	unlock()
}

var auditLockExitTestHold func()

func TestAcquireAuditLock_ExitHolderProcess(t *testing.T) {
	path := os.Getenv("TG_TEST_AUDIT_LOCK_EXIT_PATH")
	if path == "" {
		t.Skip("helper process only")
	}
	var err error
	auditLockExitTestHold, err = acquireAuditLock(path)
	if err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}
	// Keep the descriptor reachable until the test process exits. Do not call
	// the closure: the parent is testing kernel cleanup on process termination.
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

func TestAppendHookAudit_ExtendsEOFTerminatedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := hookAuditTraceOfSize(t, 1024)
	line, err := audit.MarshalTraceRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	// EOF is a valid terminator for the verifier. The resumed writer must add
	// the missing JSONL delimiter before its next object.
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append after EOF-terminated record: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("}\n{")) {
		t.Fatalf("resumed audit has no record delimiter: %q", raw)
	}
	report, err := audit.VerifyChainFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact || report.Records != 2 {
		t.Fatalf("EOF-resumed hook chain = %#v, want intact with 2 records", report)
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

func TestAppendHookAudit_ExtendsExactMaxRecordAfterBlankLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append([]byte(nil), line...), []byte("\n\r\n\n\r\n\n")...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append after blank-line suffix: %v", err)
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
	if !report.Intact || report.Records != 2 {
		t.Fatalf("blank-line suffix chain = %#v, want intact with 2 records", report)
	}
}

func TestAppendHookAudit_ExtendsExactMaxRecordEndingBareCR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append([]byte(nil), line...), '\r')
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := audit.VerifyChainFromReader(bytes.NewReader(contents))
	if err != nil || !before.Intact || before.Records != 1 {
		t.Fatalf("bare-CR seed verification = %#v, err=%v", before, err)
	}
	if err := appendHookAudit(path, auditEnv("next"), nil, "allow", "ok"); err != nil {
		t.Fatalf("append after exact-max bare-CR record: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("\r\n{")) {
		t.Fatalf("bare CR was not completed as a CRLF delimiter")
	}
	report, err := audit.VerifyChainFromReader(bytes.NewReader(raw))
	if err != nil || !report.Intact || report.Records != 2 {
		t.Fatalf("bare-CR resumed chain = %#v, err=%v", report, err)
	}
}

func TestAppendHookAudit_RejectsDetachedSuffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "audit", "testdata", "v2-then-v070-hook.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(fixture), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("fixture lines = %d, want 2", len(lines))
	}
	contents := append(append([]byte(nil), lines[1]...), '\n')
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	err = appendHookAudit(path, auditEnv("next"), nil, "allow", "ok")
	if err == nil || !strings.Contains(err.Error(), "previous_trace_hash must be empty") {
		t.Fatalf("append error = %v, want detached-genesis rejection", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, contents) {
		t.Fatal("rejected detached-suffix append changed the audit file")
	}
}

func TestAppendHookAuditBestEffort_RejectsCanonicalVersionDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "audit", "testdata", "v2-then-v070-hook.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	appendHookAuditBestEffort(&stderr, path, auditEnv("next"), nil, "allow", "ok")
	if got := stderr.String(); !strings.Contains(got, "audit append failed") || !strings.Contains(got, "canonical version downgrade") {
		t.Fatalf("stderr = %q, want surfaced canonical-downgrade warning", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, fixture) {
		t.Fatal("rejected canonical-downgrade append changed the audit file")
	}
}

func TestAppendHookAudit_RejectsTamperedTailHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := appendHookAudit(path, auditEnv("first"), nil, "allow", "ok"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var trace domain.DecisionTrace
	if err := json.Unmarshal(bytes.TrimSpace(raw), &trace); err != nil {
		t.Fatal(err)
	}
	trace.TraceHash = "sha256:forged"
	tampered, err := json.Marshal(&trace)
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, '\n')
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	err = appendHookAudit(path, auditEnv("next"), nil, "allow", "ok")
	if err == nil || !strings.Contains(err.Error(), "trace_hash") {
		t.Fatalf("append error = %v, want tampered-hash rejection", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, tampered) {
		t.Fatal("rejected tampered-tail append changed the audit file")
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
	if err == nil || !strings.Contains(err.Error(), "record exceeds") {
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
	if err == nil || !strings.Contains(err.Error(), "parse JSON") {
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
