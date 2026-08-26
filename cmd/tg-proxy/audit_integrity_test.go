package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// makeValidTrace builds one trace whose TraceHash matches the canonical
// recomputation and whose PreviousTraceHash links to prevHash — mirrors
// pkg/audit's own (unexported) makeTrace test helper, reimplemented here
// because it isn't exported across package boundaries.
func makeValidTrace(traceID, prevHash string, ts time.Time) domain.DecisionTrace {
	tr := domain.DecisionTrace{
		TraceID:           traceID,
		EnvelopeID:        "env-" + traceID,
		Timestamp:         ts,
		Decision:          domain.DecisionAllowed,
		ActionTaken:       domain.ActionAllowed,
		PreviousTraceHash: prevHash,
	}
	h, err := audit.ComputeCanonicalTraceHash(&tr)
	if err != nil {
		panic("makeValidTrace: " + err.Error())
	}
	tr.TraceHash = h
	return tr
}

func makeSizedProxyTrace(t *testing.T, target int) domain.DecisionTrace {
	t.Helper()
	tr := domain.DecisionTrace{
		CanonicalVersion: audit.CanonicalTraceVersion,
		TraceID:          "trc-size-boundary",
		EnvelopeID:       "env-size-boundary",
		Timestamp:        time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		ToolName:         "bash",
		Decision:         domain.DecisionAllowed,
		ActionTaken:      domain.ActionAllowed,
		DecisionReason:   "x",
	}

	marshalRehashed := func() []byte {
		tr.TraceHash = ""
		h, err := audit.ComputeCanonicalTraceHash(&tr)
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

func writeTracesJSONL(t *testing.T, path string, traces []domain.DecisionTrace) {
	t.Helper()
	var buf bytes.Buffer
	for _, tr := range traces {
		b, err := json.Marshal(tr)
		if err != nil {
			t.Fatalf("marshal trace: %v", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

// TestOpenAuditLog_IntactChain_Starts proves the happy path still works:
// a genuinely unbroken chain must NOT block startup.
func TestOpenAuditLog_IntactChain_Starts(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")
	ts := time.Now().Truncate(time.Microsecond)
	t1 := makeValidTrace("t1", "", ts)
	t2 := makeValidTrace("t2", t1.TraceHash, ts.Add(time.Second))
	t3 := makeValidTrace("t3", t2.TraceHash, ts.Add(2*time.Second))
	writeTracesJSONL(t, active, []domain.DecisionTrace{t1, t2, t3})

	p := &proxy{auditPath: active}
	if err := p.openAuditLog(); err != nil {
		t.Fatalf("openAuditLog on an intact chain must succeed, got: %v", err)
	}
	if p.auditLog != nil {
		_ = p.auditLog.Close()
	}
	if p.lastHash != t3.TraceHash {
		t.Errorf("lastHash = %q, want tail %q", p.lastHash, t3.TraceHash)
	}
}

// TestOpenAuditLog_MiddleRecordBrokenLink_RefusesToStart is the core new
// guarantee: a tampered record in the MIDDLE of the file (not the tail)
// must refuse startup. Before this change, openAuditLog only verified the
// LAST record's self-consistency — a broken prev_hash link earlier in the
// file was invisible to it, because the tail record's own hash can still
// be perfectly valid even when an earlier link in the chain was cut.
func TestOpenAuditLog_MiddleRecordBrokenLink_RefusesToStart(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")
	ts := time.Now().Truncate(time.Microsecond)
	t1 := makeValidTrace("t1", "", ts)
	t2 := makeValidTrace("t2", t1.TraceHash, ts.Add(time.Second))
	// t3 does NOT link to t2 — simulates a record spliced/replaced in the
	// middle of the file. t3's own TraceHash is still internally valid
	// (computed correctly for its own content), so a tail-only check would
	// never see this: the chain's actual tail (t4) links correctly to t3,
	// so the LAST record alone looks fine.
	forged := makeValidTrace("t3-forged", "sha256:not-t2-hash-at-all", ts.Add(2*time.Second))
	t4 := makeValidTrace("t4", forged.TraceHash, ts.Add(3*time.Second))
	writeTracesJSONL(t, active, []domain.DecisionTrace{t1, t2, forged, t4})

	p := &proxy{auditPath: active}
	err := p.openAuditLog()
	if err == nil {
		if p.auditLog != nil {
			_ = p.auditLog.Close()
		}
		t.Fatal("openAuditLog must refuse to start on a chain with a broken middle link, got nil error")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("error should describe an integrity failure, got: %v", err)
	}
}

func TestOpenAuditLog_DetachedSuffix_RefusesToStart(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "audit", "testdata", "v2-then-v070-hook.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(fixture), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("fixture lines = %d, want 2", len(lines))
	}
	if err := os.WriteFile(active, append(lines[1], '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &proxy{auditPath: active, lastHash: "sha256:stale-from-prior-attempt"}
	err = p.openAuditLog()
	if err == nil {
		if p.auditLog != nil {
			_ = p.auditLog.Close()
		}
		t.Fatal("openAuditLog must refuse a detached suffix with a dangling previous hash")
	}
	if !strings.Contains(err.Error(), "genesis previous_trace_hash") {
		t.Fatalf("detached-suffix error = %v, want genesis failure", err)
	}
	if p.lastHash != "" {
		t.Fatalf("failed open retained untrusted lastHash %q", p.lastHash)
	}
}

// TestOpenAuditLog_BrokenLinkAcrossRotationBoundary_RefusesToStart proves
// the full-chain check walks the WHOLE rotation set (not just the active
// file) — a break at the seam between a rotated sibling and the active
// file must be caught exactly like a break within one file.
func TestOpenAuditLog_BrokenLinkAcrossRotationBoundary_RefusesToStart(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")
	ts := time.Now().Truncate(time.Microsecond)

	t1 := makeValidTrace("t1", "", ts)
	t2 := makeValidTrace("t2", t1.TraceHash, ts.Add(time.Second))
	writeTracesJSONL(t, active+".1", []domain.DecisionTrace{t1, t2})

	// Active file's first record should link to t2's hash but doesn't.
	t3 := makeValidTrace("t3", "sha256:wrong-does-not-match-t2", ts.Add(2*time.Second))
	writeTracesJSONL(t, active, []domain.DecisionTrace{t3})

	p := &proxy{auditPath: active}
	err := p.openAuditLog()
	if err == nil {
		if p.auditLog != nil {
			_ = p.auditLog.Close()
		}
		t.Fatal("openAuditLog must refuse to start when the break is across a rotation boundary, got nil error")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("error should describe an integrity failure, got: %v", err)
	}
}

// TestOpenAuditLog_NoExistingFile_Starts proves a fresh install (no audit
// file yet) is not mistaken for a broken chain — nothing to verify yet.
func TestOpenAuditLog_NoExistingFile_Starts(t *testing.T) {
	dir := t.TempDir()
	p := &proxy{auditPath: filepath.Join(dir, "decisions.jsonl")}
	if err := p.openAuditLog(); err != nil {
		t.Fatalf("openAuditLog on a fresh install must succeed, got: %v", err)
	}
	if p.auditLog != nil {
		_ = p.auditLog.Close()
	}
}

func TestAppendTrace_RecordSizeBoundaryVerifyAndRestart(t *testing.T) {
	t.Run("exact max", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "decisions.jsonl")
		p := &proxy{auditPath: path, auditSyncMode: "none"}
		if err := p.openAuditLog(); err != nil {
			t.Fatalf("open audit log: %v", err)
		}
		trace := makeSizedProxyTrace(t, audit.MaxTraceRecordBytes)
		if err := p.appendTrace(&trace); err != nil {
			t.Fatalf("append exact-max record: %v", err)
		}
		if err := p.auditLog.Close(); err != nil {
			t.Fatalf("close audit log: %v", err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != int64(audit.MaxTraceRecordBytes+1) {
			t.Fatalf("audit file size = %d, want record plus LF = %d", st.Size(), audit.MaxTraceRecordBytes+1)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		report, verifyErr := audit.VerifyChainFromReader(f)
		_ = f.Close()
		if verifyErr != nil {
			t.Fatalf("verify exact-max record: %v", verifyErr)
		}
		if !report.Intact || report.Records != 1 {
			t.Fatalf("exact-max report = %#v, want intact one-record chain", report)
		}

		restarted := &proxy{auditPath: path, auditSyncMode: "none"}
		if err := restarted.openAuditLog(); err != nil {
			t.Fatalf("restart after exact-max record: %v", err)
		}
		defer restarted.auditLog.Close()
		if restarted.lastHash != trace.TraceHash {
			t.Fatalf("recovered tail = %q, want %q", restarted.lastHash, trace.TraceHash)
		}
	})

	t.Run("max plus one is rejected without poisoning the chain", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "decisions.jsonl")
		p := &proxy{auditPath: path, auditSyncMode: "none"}
		if err := p.openAuditLog(); err != nil {
			t.Fatalf("open audit log: %v", err)
		}
		tooLarge := makeSizedProxyTrace(t, audit.MaxTraceRecordBytes+1)
		if err := p.appendTrace(&tooLarge); err == nil || !strings.Contains(err.Error(), "maximum") {
			t.Fatalf("append max+1 error = %v, want record-size rejection", err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != 0 || p.lastHash != "" || p.auditCurrentBytes != 0 {
			t.Fatalf("rejected append mutated chain: size=%d lastHash=%q currentBytes=%d", st.Size(), p.lastHash, p.auditCurrentBytes)
		}

		small := domain.DecisionTrace{
			TraceID:     "trc-after-rejection",
			EnvelopeID:  "env-after-rejection",
			Timestamp:   time.Date(2026, 8, 25, 0, 0, 1, 0, time.UTC),
			ToolName:    "bash",
			Decision:    domain.DecisionAllowed,
			ActionTaken: domain.ActionAllowed,
		}
		if err := p.appendTrace(&small); err != nil {
			t.Fatalf("append after rejected oversized record: %v", err)
		}
		if err := p.auditLog.Close(); err != nil {
			t.Fatalf("close audit log: %v", err)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		report, verifyErr := audit.VerifyChainFromReader(f)
		_ = f.Close()
		if verifyErr != nil {
			t.Fatalf("verify chain after rejection: %v", verifyErr)
		}
		if !report.Intact || report.Records != 1 {
			t.Fatalf("post-rejection report = %#v, want intact one-record chain", report)
		}

		restarted := &proxy{auditPath: path, auditSyncMode: "none"}
		if err := restarted.openAuditLog(); err != nil {
			t.Fatalf("restart after rejected oversized record: %v", err)
		}
		defer restarted.auditLog.Close()
		if restarted.lastHash != small.TraceHash {
			t.Fatalf("recovered tail = %q, want %q", restarted.lastHash, small.TraceHash)
		}
	})
}
