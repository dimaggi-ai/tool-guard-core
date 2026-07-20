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
