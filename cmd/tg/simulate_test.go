package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func captureSimulateOutput(t *testing.T, run func() int) (int, []byte) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	type readResult struct {
		out []byte
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		out, readErr := io.ReadAll(r)
		done <- readResult{out: out, err: readErr}
	}()
	code := run()
	_ = w.Close()
	os.Stdout = oldStdout
	read := <-done
	_ = r.Close()
	if read.err != nil {
		t.Fatal(read.err)
	}
	return code, read.out
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

func TestSimulate_ShadowDeniesAreReportedButDoNotFailAppliedActionGate(t *testing.T) {
	shadowPolicy := strings.Replace(simPolicy, "mode: enforcement", "mode: shadow", 1)
	pol := writeTemp(t, "shadow.yaml", shadowPolicy)
	calls := writeTemp(t, "calls.jsonl", simCalls)

	code, out := captureSimulateOutput(t, func() int {
		return cmdSimulate([]string{"-policy", pol, "-calls", calls, "-json", "-fail-on-deny"})
	})

	if code != 0 {
		t.Fatalf("shadow-only simulation must not fail the applied-deny gate; exit = %d, output=%s", code, out)
	}
	var summary struct {
		Decisions map[string]int `json:"decisions"`
		Actions   map[string]int `json:"actions"`
	}
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatalf("decode simulation JSON: %v; output=%s", err, out)
	}
	if summary.Decisions["denied"] != 2 {
		t.Errorf("raw denied decisions = %d, want 2", summary.Decisions["denied"])
	}
	if summary.Actions["allowed_shadow"] != 2 || summary.Actions["denied"] != 0 {
		t.Errorf("applied actions = %#v, want allowed_shadow=2 and denied=0", summary.Actions)
	}
}

func TestSimulate_FailOnDenyRejectsMalformedCorpus(t *testing.T) {
	pol := writeTemp(t, "pol.yaml", simPolicy)
	tests := []struct {
		name  string
		calls string
	}{
		{name: "all malformed", calls: "not-json\n"},
		{name: "partially malformed", calls: simCalls + "not-json\n"},
		{name: "null envelope", calls: "null\n"},
		{name: "empty object", calls: "{}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := writeTemp(t, "calls.jsonl", tt.calls)
			code, out := captureSimulateOutput(t, func() int {
				return cmdSimulate([]string{"-policy", pol, "-calls", calls, "-json", "-fail-on-deny"})
			})
			if code != 1 {
				t.Fatalf("malformed gated simulation exit = %d, want 1; output=%s", code, out)
			}
			var summary struct {
				Malformed int `json:"malformed"`
			}
			if err := json.Unmarshal(out, &summary); err != nil {
				t.Fatalf("decode simulation JSON: %v; output=%s", err, out)
			}
			if summary.Malformed != 1 {
				t.Fatalf("malformed count = %d, want 1", summary.Malformed)
			}
		})
	}
}

func TestSimulate_FailOnDenyRejectsEmptyCorpus(t *testing.T) {
	pol := writeTemp(t, "pol.yaml", simPolicy)
	for _, tt := range []struct {
		name  string
		calls string
	}{
		{name: "empty", calls: ""},
		{name: "whitespace only", calls: " \n\t\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := writeTemp(t, "calls.jsonl", tt.calls)
			code, out := captureSimulateOutput(t, func() int {
				return cmdSimulate([]string{"-policy", pol, "-calls", calls, "-json", "-fail-on-deny"})
			})
			if code != 1 {
				t.Fatalf("empty gated simulation exit = %d, want 1; output=%s", code, out)
			}
			var summary struct {
				Total     int `json:"total"`
				Malformed int `json:"malformed"`
			}
			if err := json.Unmarshal(out, &summary); err != nil {
				t.Fatalf("decode simulation JSON: %v; output=%s", err, out)
			}
			if summary.Total != 0 || summary.Malformed != 0 {
				t.Fatalf("empty summary = %#v, want total=0 and malformed=0", summary)
			}
		})
	}
}

func TestSimulate_TableReportsAppliedActions(t *testing.T) {
	shadowPolicy := strings.Replace(simPolicy, "mode: enforcement", "mode: shadow", 1)
	pol := writeTemp(t, "shadow.yaml", shadowPolicy)
	calls := writeTemp(t, "calls.jsonl", simCalls)
	code, out := captureSimulateOutput(t, func() int {
		return cmdSimulate([]string{"-policy", pol, "-calls", calls})
	})
	if code != 0 {
		t.Fatalf("table simulation exit = %d, output=%s", code, out)
	}
	text := string(out)
	if !strings.Contains(text, "applied actions (what would execute):") {
		t.Fatalf("table output missing applied-actions section:\n%s", text)
	}
	found := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "allowed_shadow" {
			found = true
			if fields[1] != "2" {
				t.Errorf("allowed_shadow count = %s, want 2; line=%q", fields[1], line)
			}
		}
	}
	if !found {
		t.Fatalf("table output missing allowed_shadow count:\n%s", text)
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

func TestLoadPolicySet_RejectsDuplicatePolicyIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "first.yaml"), []byte(simPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	second := strings.Replace(simPolicy, "rule_id: cap", "rule_id: second-cap", 1)
	if err := os.WriteFile(filepath.Join(dir, "second.yaml"), []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicySet(dir, ""); err == nil || !strings.Contains(err.Error(), "duplicate policy identity") {
		t.Fatalf("loadPolicySet duplicate-identity error = %v", err)
	}
}
