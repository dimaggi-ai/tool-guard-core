package main

// A tool call can carry the same thing under two parameter names. Measured
// 2026-11-09 on the tree that only placed each value on a canonical key: with
// {"Cmd":"echo hi","CommandLine":"rm -rf /"} the hook put "echo hi" on
// parameters.command and the rm command on parameters.cmd, which no rule
// reads, and returned allow 20 times out of 20. The same happened for a second
// content value and for a third path value. hookParamVariants now evaluates
// every distinct value. These tests pin that at the stdin and stdout boundary
// with a policy of their own: every distinct value is evaluated, the most
// restrictive decision is returned, a call with one value per family keeps its
// decision, and one call writes one audit record.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const aliasVariantPolicy = `policy_id: alias-variant-test
name: alias-variant-test
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash, write]
  tool_groups: [shell, filesystem_writes]
rules:
  - rule_id: deny-rm
    conditions:
      field: parameters.command
      operator: regex
      value: 'rm -rf'
    effect: deny
    citation: {document_id: d, excerpt: "no rm"}
  - rule_id: escalate-git
    conditions:
      field: parameters.command
      operator: regex
      value: 'git'
    effect: escalate
    effect_config:
      severity: medium
      escalate_to: human
      timeout_minutes: 15
    citation: {document_id: d, excerpt: "git needs review"}
  - rule_id: deny-marked-content
    conditions:
      field: parameters.content
      operator: regex
      value: 'SYNTHETIC-MARK'
    effect: deny
    citation: {document_id: d, excerpt: "no marked content"}
  - rule_id: deny-agents-file
    conditions:
      field: parameters.file_path
      operator: regex
      value: 'AGENTS\.md$'
    effect: deny
    citation: {document_id: d, excerpt: "no instruction file"}
`

// aliasVariantDecision reads the decision from either output dialect.
func aliasVariantDecision(t *testing.T, output string) (decision, reason string) {
	t.Helper()
	var o struct {
		Decision           string `json:"decision"`
		Reason             string `json:"reason"`
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &o); err != nil {
		t.Fatalf("hook stdout is not valid JSON: %v\n%s", err, output)
	}
	if o.Decision != "" {
		return o.Decision, o.Reason
	}
	return o.HookSpecificOutput.PermissionDecision, o.HookSpecificOutput.PermissionDecisionReason
}

// aliasVariantSend sends one payload 20 times and requires the same decision
// every time.
func aliasVariantSend(t *testing.T, payload string, args ...string) string {
	t.Helper()
	first := ""
	for i := 0; i < 20; i++ {
		out, code := runHookStr(t, payload, args...)
		if code != 0 {
			t.Fatalf("hook must exit 0, got %d", code)
		}
		dec, _ := aliasVariantDecision(t, out)
		if i == 0 {
			first = dec
		} else if dec != first {
			t.Fatalf("send %d returned %q, send 1 returned %q, for the same payload %s", i+1, dec, first, payload)
		}
	}
	return first
}

func TestHookEvaluatesEveryAliasValue(t *testing.T) {
	pol := writeHookPolicy(t, aliasVariantPolicy)
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"claude shell, canonical key harmless, alias destructive",
			`{"tool_name":"Bash","tool_input":{"command":"echo hi","cmd":"rm -rf /tmp/x"}}`, "deny"},
		{"antigravity shell, first alias harmless, second destructive",
			`{"toolCall":{"name":"run_command","args":{"Cmd":"echo hi","CommandLine":"rm -rf /tmp/x"}}}`, "deny"},
		{"antigravity shell, canonical key harmless, alias destructive",
			`{"toolCall":{"name":"run_command","args":{"command":"echo hi","CommandLine":"rm -rf /tmp/x"}}}`, "deny"},
		{"antigravity shell, first alias destructive, second harmless",
			`{"toolCall":{"name":"run_command","args":{"Cmd":"rm -rf /tmp/x","CommandLine":"echo hi"}}}`, "deny"},
		{"claude shell, three values, deny wins over ask",
			`{"tool_name":"Bash","tool_input":{"command":"echo hi","cmd":"git status","script":"rm -rf /tmp/x"}}`, "deny"},
		{"claude shell, two values, ask wins over allow",
			`{"tool_name":"Bash","tool_input":{"command":"echo hi","cmd":"git status"}}`, "ask"},
		{"claude write, canonical content harmless, alias marked",
			`{"tool_name":"Write","tool_input":{"file_path":"notes.txt","content":"harmless","text":"SYNTHETIC-MARK"}}`, "deny"},
		{"antigravity write, first content alias harmless, second marked",
			`{"toolCall":{"name":"write_file","args":{"Path":"notes.txt","Content":"harmless","Text":"SYNTHETIC-MARK"}}}`, "deny"},
		{"antigravity write, third path value is the instruction file",
			`{"toolCall":{"name":"write_file","args":{"File":"a.txt","Filename":"plain.txt","Path":"/w/AGENTS.md","Content":"a"}}}`, "deny"},
		{"antigravity write, canonical and second key harmless, alias is the instruction file",
			`{"toolCall":{"name":"write_file","args":{"file_path":"a.txt","path":"b.txt","Path":"/w/AGENTS.md","Content":"a"}}}`, "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aliasVariantSend(t, tc.payload, "-policy", pol); got != tc.want {
				t.Errorf("decision = %q, want %q, for %s", got, tc.want, tc.payload)
			}
		})
	}
}

func TestHookSingleValueCallsKeepTheirDecision(t *testing.T) {
	pol := writeHookPolicy(t, aliasVariantPolicy)
	cases := []struct {
		payload string
		want    string
	}{
		{`{"tool_name":"Bash","tool_input":{"command":"echo hi","description":"say hi"}}`, "allow"},
		{`{"tool_name":"Bash","tool_input":{"command":"git status"}}`, "ask"},
		{`{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}`, "deny"},
		{`{"tool_name":"Write","tool_input":{"file_path":"notes.txt","content":"harmless"}}`, "allow"},
		{`{"tool_name":"Edit","tool_input":{"file_path":"notes.txt","old_string":"a","new_string":"b"}}`, "allow"},
		{`{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","WaitMsBeforeAsync":500,"toolSummary":"say hi"}}}`, "allow"},
		{`{"toolCall":{"name":"write_file","args":{"Path":"notes.txt","Content":"harmless","Overwrite":true}}}`, "allow"},
		{`{"toolCall":{"name":"write_file","args":{"Path":"/w/AGENTS.md","Content":"a"}}}`, "deny"},
		{`{"toolCall":{"name":"write_file","args":{"Path":"same.txt","Filename":"same.txt","Content":"a"}}}`, "allow"},
	}
	for _, tc := range cases {
		if got := aliasVariantSend(t, tc.payload, "-policy", pol); got != tc.want {
			t.Errorf("decision = %q, want %q, for %s", got, tc.want, tc.payload)
		}
	}
}

func TestHookProtectedPathReadsEveryAliasValue(t *testing.T) {
	pol := writeHookPolicy(t, aliasVariantPolicy)
	protected := filepath.Join(t.TempDir(), "protected")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(protected, "x")
	cases := []struct {
		name    string
		payload string
	}{
		{"second command value redirects into the protected directory",
			fmt.Sprintf(`{"toolCall":{"name":"run_command","args":{"Cmd":"echo hi","CommandLine":"echo x > %s"}}}`, target)},
		{"canonical command harmless, alias redirects into the protected directory",
			fmt.Sprintf(`{"tool_name":"Bash","tool_input":{"command":"echo hi","cmd":"echo x > %s"}}`, target)},
		{"third path value is in the protected directory",
			fmt.Sprintf(`{"toolCall":{"name":"write_file","args":{"File":"a.txt","Filename":"plain.txt","Path":"%s","Content":"a"}}}`, target)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aliasVariantSend(t, tc.payload, "-policy", pol, "-protect-path", protected); got != "deny" {
				t.Errorf("decision = %q, want deny, for %s", got, tc.payload)
			}
		})
	}
}

// TestHookAliasLimitIsNeverAllowed sends one more distinct path value than
// twice the limit hookParamVariants evaluates. The hook escalates such a call.
// The Codex wrapper of the example passes -escalate-as deny: with that flag the same
// call must be denied in both dialects.
func TestHookAliasLimitIsNeverAllowed(t *testing.T) {
	pol := writeHookPolicy(t, aliasVariantPolicy)
	// 33 spellings of one alias name, each with its own value.
	args := map[string]string{"Content": "a"}
	word := "filename"
	for i := 0; i < 33; i++ {
		key := []byte(word)
		for bit := 0; bit < len(key); bit++ {
			if i&(1<<bit) != 0 {
				key[bit] = key[bit] - 'a' + 'A'
			}
		}
		args[string(key)] = fmt.Sprintf("file-%02d.txt", i)
	}
	cases := []struct {
		name   string
		tool   string
		flags  []string
		wanted []string
	}{
		{"antigravity dialect, no flag", "toolCall", nil, []string{"force_ask"}},
		{"antigravity dialect, -escalate-as deny", "toolCall", []string{"-escalate-as", "deny"}, []string{"deny"}},
		{"claude dialect, no flag", "tool_name", nil, []string{"ask"}},
		{"claude dialect, -escalate-as deny", "tool_name", []string{"-escalate-as", "deny"}, []string{"deny"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"toolCall": map[string]any{"name": "write_file", "args": args}}
			if tc.tool == "tool_name" {
				payload = map[string]any{"tool_name": "Write", "tool_input": args}
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			out, code := runHookStr(t, string(raw), append([]string{"-policy", pol}, tc.flags...)...)
			if code != 0 {
				t.Fatalf("hook must exit 0, got %d", code)
			}
			dec, reason := aliasVariantDecision(t, out)
			if !slices.Contains(tc.wanted, dec) {
				t.Fatalf("decision = %q, want one of %q", dec, tc.wanted)
			}
			if !strings.Contains(reason, "parameter-spelling limit") {
				t.Errorf("the reason must say that not every value was evaluated, got %q", reason)
			}
		})
	}
}

func TestHookAliasVariantsWriteOneAuditRecord(t *testing.T) {
	pol := writeHookPolicy(t, aliasVariantPolicy)
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	payload := `{"toolCall":{"name":"run_command","args":{"Cmd":"echo hi","CommandLine":"git status","Script":"rm -rf /tmp/x"}}}`
	out, _ := runHookStr(t, payload, "-policy", pol, "-audit-log", log)
	if dec, _ := aliasVariantDecision(t, out); dec != "deny" {
		t.Fatalf("decision = %q, want deny", dec)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; n != 1 {
		t.Errorf("one call must write one audit record, the log has %d lines", n)
	}
	if !strings.Contains(string(raw), `"rule_id":"deny-rm"`) {
		t.Errorf("the audit record must name the rule that produced the decision, got %s", raw)
	}
}
