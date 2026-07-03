package main

import (
	"os"
	"path/filepath"
	"testing"
)

const simPolicy = `policy_id: sim-pol
name: sim-refund-cap
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
rules:
  - rule_id: cap
    name: per-call cap
    conditions: {field: amount, operator: gt, value: 500}
    effect: deny
    citation: {document_id: D, excerpt: X}
`

const simCalls = `{"envelope_id":"a","tool_name":"issue_refund","parameters":{"amount":100}}
{"envelope_id":"b","tool_name":"issue_refund","parameters":{"amount":9000}}
{"envelope_id":"c","tool_name":"issue_refund","parameters":{"amount":600}}
{"envelope_id":"d","tool_name":"issue_refund","parameters":{"amount":50}}
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSimulate_CountsDecisionsAndRuleFires(t *testing.T) {
	pol := writeTemp(t, "pol.yaml", simPolicy)
	calls := writeTemp(t, "calls.jsonl", simCalls)

	// Default run exits 0 even with denials.
	if code := cmdSimulate([]string{"-policy", pol, "-calls", calls}); code != 0 {
		t.Errorf("simulate exit = %d, want 0", code)
	}
	// -fail-on-deny flips to 3 because 2 of the 4 calls exceed the cap.
	if code := cmdSimulate([]string{"-policy", pol, "-calls", calls, "-fail-on-deny"}); code != 3 {
		t.Errorf("simulate -fail-on-deny exit = %d, want 3 (denials present)", code)
	}
}

func TestSimulate_JSONMode(t *testing.T) {
	pol := writeTemp(t, "pol.yaml", simPolicy)
	calls := writeTemp(t, "calls.jsonl", simCalls)
	if code := cmdSimulate([]string{"-policy", pol, "-calls", calls, "-json"}); code != 0 {
		t.Errorf("json simulate exit = %d, want 0", code)
	}
}

func TestSimulate_UsageErrors(t *testing.T) {
	pol := writeTemp(t, "pol.yaml", simPolicy)
	calls := writeTemp(t, "calls.jsonl", simCalls)

	cases := [][]string{
		{"-calls", calls}, // no policy
		{"-policy", pol, "-policy-dir", ".", "-calls", calls}, // both policy selectors
		{"-policy", pol}, // no calls
		{"-policy", pol, "-calls", calls, "-mode", "bogus"}, // bad mode
	}
	for i, args := range cases {
		if code := cmdSimulate(args); code != 2 {
			t.Errorf("case %d: exit = %d, want 2 (usage error)", i, code)
		}
	}
}

func TestSimulate_PolicyDirLoadsMultiple(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(simPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := writeTemp(t, "calls.jsonl", simCalls)
	if code := cmdSimulate([]string{"-policy-dir", dir, "-calls", calls}); code != 0 {
		t.Errorf("policy-dir simulate exit = %d, want 0", code)
	}
}

func TestLoadPolicySet_ValidatesBadPolicy(t *testing.T) {
	bad := `policy_id: bad
name: bad
version: 1
status: approved
mode: enforcement
scope: {tool_names: [x]}
rules:
  - rule_id: r
    name: r
    conditions: {field: amount, operator: regex, value: "([unclosed"}
    effect: deny
    citation: {document_id: D, excerpt: X}
`
	p := writeTemp(t, "bad.yaml", bad)
	if _, err := loadPolicySet("", p); err == nil {
		t.Error("expected loadPolicySet to reject a policy with an uncompilable regex")
	}
}
