package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
			TraceHash string `json:"trace_hash"`
			PrevHash  string `json:"previous_trace_hash"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
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
		if err := appendHookAudit(path, auditEnv("env"), "allow", "ok"); err != nil {
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
			_ = appendHookAudit(path, auditEnv("env"), "allow", "ok")
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
		if err := appendHookAudit(path, auditEnv("env"), "allow", strings.Repeat("x", 300)); err != nil {
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
