package main

import (
	"os"
	"path/filepath"
	"testing"
)

const covPolicy = `policy_id: cov-pol
name: cov-refund
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
rules:
  - rule_id: r
    name: cap
    conditions: {field: amount, operator: gt, value: 500}
    effect: deny
    citation: {document_id: D, excerpt: X}
`

// Two of four calls are for the governed tool (issue_refund); the other two
// (send_email, http) have no policy → 50% coverage.
const covCalls = `{"tool_name":"issue_refund","parameters":{"amount":100}}
{"tool_name":"issue_refund","parameters":{"amount":9000}}
{"tool_name":"send_email"}
{"tool_name":"http","tool_input":{"url":"https://x"}}
`

func writeTmp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCoverage_ExitAndMinCoverage(t *testing.T) {
	pol := writeTmp(t, "p.yaml", covPolicy)
	calls := writeTmp(t, "c.jsonl", covCalls)

	if code := cmdCoverage([]string{"-policy", pol, "-calls", calls}); code != 0 {
		t.Errorf("default exit = %d, want 0", code)
	}
	// Coverage is 50% (2 of 4). -min-coverage 80 → below → exit 3.
	if code := cmdCoverage([]string{"-policy", pol, "-calls", calls, "-min-coverage", "80"}); code != 3 {
		t.Errorf("-min-coverage 80 exit = %d, want 3 (coverage is 50%%)", code)
	}
	// -min-coverage 40 → above → exit 0.
	if code := cmdCoverage([]string{"-policy", pol, "-calls", calls, "-min-coverage", "40"}); code != 0 {
		t.Errorf("-min-coverage 40 exit = %d, want 0", code)
	}
}

func TestCoverage_JSONAndUsage(t *testing.T) {
	pol := writeTmp(t, "p.yaml", covPolicy)
	calls := writeTmp(t, "c.jsonl", covCalls)
	if code := cmdCoverage([]string{"-policy", pol, "-calls", calls, "-json"}); code != 0 {
		t.Errorf("json exit = %d, want 0", code)
	}
	// Usage errors.
	for i, args := range [][]string{
		{"-calls", calls},                    // no policy
		{"-policy", pol},                     // no calls
		{"-policy", pol, "-policy-dir", "."}, // both selectors + no calls handled first? both selectors errors
	} {
		if code := cmdCoverage(args); code != 2 {
			t.Errorf("usage case %d: exit = %d, want 2", i, code)
		}
	}
}

// A trace-shaped line (has trace_hash/decision but the same identity fields)
// must be counted the same as an envelope — coverage runs on audit logs.
func TestCoverage_AcceptsTraceShapes(t *testing.T) {
	pol := writeTmp(t, "p.yaml", covPolicy)
	traces := `{"trace_id":"t1","tool_name":"issue_refund","decision":"denied","trace_hash":"sha256:x"}
{"trace_id":"t2","tool_name":"send_email","decision":"allowed","trace_hash":"sha256:y"}
`
	calls := writeTmp(t, "traces.jsonl", traces)
	// 1 of 2 governed = 50%; min 60 → exit 3, confirming trace lines were parsed.
	if code := cmdCoverage([]string{"-policy", pol, "-calls", calls, "-min-coverage", "60"}); code != 3 {
		t.Errorf("trace-shaped input exit = %d, want 3 (50%% governed)", code)
	}
}
