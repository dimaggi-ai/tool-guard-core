package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRecoverAuditTail_AfterRotation proves the chain is recovered from
// the newest rotated sibling when the active file is empty — the case a
// restart right after a size rotation produces. Before the fix, the
// startup scan looked only at the (empty) active file and reset the
// chain.
func TestRecoverAuditTail_AfterRotation(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")

	// Two rotated siblings with records; the newest (.2) holds the tail.
	older := `{"trace_id":"trc-1","trace_hash":"sha256:aaa"}`
	newer := `{"trace_id":"trc-2","trace_hash":"sha256:bbb"}
{"trace_id":"trc-3","trace_hash":"sha256:ccc"}`
	if err := os.WriteFile(active+".1", []byte(older+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active+".2", []byte(newer+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Active file exists but is empty (post-rotation state).
	if err := os.WriteFile(active, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	p := &proxy{auditPath: active}

	// Newest-first ordering: active, then .2, then .1.
	got := p.auditCandidatesNewestFirst()
	want := []string{active, active + ".2", active + ".1"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	last, sawAny, err := p.recoverAuditTail()
	if err != nil {
		t.Fatal(err)
	}
	if !sawAny {
		t.Fatal("recoverAuditTail found nothing; should have read the rotated tail")
	}
	if last.TraceID != "trc-3" {
		t.Fatalf("recovered tail = %q, want trc-3 (last record of newest non-empty file)", last.TraceID)
	}
}

// TestRecoverAuditTail_NoFiles returns sawAny=false cleanly when nothing
// exists yet (fresh install).
func TestRecoverAuditTail_NoFiles(t *testing.T) {
	dir := t.TempDir()
	p := &proxy{auditPath: filepath.Join(dir, "decisions.jsonl")}
	_, sawAny, err := p.recoverAuditTail()
	if err != nil {
		t.Fatal(err)
	}
	if sawAny {
		t.Fatal("recoverAuditTail should find nothing on a fresh install")
	}
}
