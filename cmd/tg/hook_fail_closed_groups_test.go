package main

// -fail-closed-tools is a list of tool NAMES. Measured 2026-11-09: with
// "-fail-closed-tools bash,powershell,write,edit,notebookedit" and a policy
// directory that fails to load, a Claude Code Bash call was denied and an
// Antigravity run_command and write_file call were both allowed, because
// those names are not in the list. -fail-closed-groups closes that by naming
// tool GROUPS, which is what hookToolGroup already assigns to every tool name,
// including one the hook has never seen (group "shell").

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func failClosedGroupsDecision(t *testing.T, out string) string {
	t.Helper()
	trimmed := strings.TrimSpace(out)
	var agy struct {
		Decision string `json:"decision"`
	}
	if json.Unmarshal([]byte(trimmed), &agy) == nil && agy.Decision != "" {
		return agy.Decision
	}
	return hookDecision(t, out)
}

func TestHookFailClosedGroupsCoverEveryHarnessToolName(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-policy-dir")
	args := []string{"-policy-dir", missing, "-mode", "enforcement",
		"-fail-closed-groups", "shell,filesystem_writes,network_egress"}
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"claude Bash", `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, "deny"},
		{"claude Write", `{"tool_name":"Write","tool_input":{"file_path":"/w/a","content":"x"}}`, "deny"},
		{"claude MultiEdit", `{"tool_name":"MultiEdit","tool_input":{"file_path":"/w/a","edits":[]}}`, "deny"},
		{"claude WebFetch", `{"tool_name":"WebFetch","tool_input":{"url":"https://example.com/"}}`, "deny"},
		{"codex apply_patch", `{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch"}}`, "deny"},
		{"antigravity run_command", `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`, "deny"},
		{"antigravity write_file", `{"toolCall":{"name":"write_file","args":{"Path":"/w/a","Content":"x"}}}`, "deny"},
		{"antigravity read_url_content", `{"toolCall":{"name":"read_url_content","args":{"Url":"https://example.com/"}}}`, "deny"},
		{"a tool name the hook has never seen", `{"tool_name":"brand_new_tool","tool_input":{}}`, "deny"},
		{"claude Read stays open", `{"tool_name":"Read","tool_input":{"file_path":"/w/a"}}`, "allow"},
		{"antigravity read_file stays open", `{"toolCall":{"name":"read_file","args":{"Path":"/w/a"}}}`, "allow"},
	}
	for _, tc := range cases {
		out, code := runHookStr(t, tc.payload, args...)
		if code != 0 {
			t.Fatalf("%s: hook must exit 0, got %d", tc.name, code)
		}
		if got := failClosedGroupsDecision(t, out); got != tc.want {
			t.Errorf("%s: decision = %q, want %q; output=%s", tc.name, got, tc.want, out)
		}
	}
}

func TestHookFailClosedToolsAloneStillMissesAntigravityNames(t *testing.T) {
	// Pins the measured gap, so nobody reads -fail-closed-tools as covering a
	// harness whose tool names are not in the list.
	missing := filepath.Join(t.TempDir(), "no-such-policy-dir")
	out, _ := runHookStr(t, `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`,
		"-policy-dir", missing, "-fail-closed-tools", "bash,powershell,write,edit,notebookedit")
	if got := failClosedGroupsDecision(t, out); got != "allow" {
		t.Fatalf("expected the documented name-list gap (allow), got %q", got)
	}
}

func TestHookFailClosedGroupsCombineWithTools(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-policy-dir")
	args := []string{"-policy-dir", missing, "-fail-closed-tools", "read", "-fail-closed-groups", "filesystem_writes"}
	for payload, want := range map[string]string{
		`{"tool_name":"Read","tool_input":{"file_path":"/w/a"}}`:                "deny",  // named tool
		`{"tool_name":"Write","tool_input":{"file_path":"/w/a","content":"x"}}`: "deny",  // listed group
		`{"tool_name":"Bash","tool_input":{"command":"ls"}}`:                    "allow", // neither
	} {
		out, _ := runHookStr(t, payload, args...)
		if got := hookDecision(t, out); got != want {
			t.Errorf("payload %s: decision = %q, want %q", payload, got, want)
		}
	}
}

func TestHookFailClosedGroupsEngageUnattributableDeny(t *testing.T) {
	out, _ := runHookStr(t, `{not json`, "-policy-dir", t.TempDir(), "-fail-closed-groups", "shell")
	if got := hookDecision(t, out); got != "deny" {
		t.Fatalf("malformed stdin with -fail-closed-groups set must be denied, got %q", got)
	}
}

func TestHookFlagParseErrorHonoursLaterFailClosedGroupsFlag(t *testing.T) {
	out, _ := runHookStr(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
		"-nope", "-fail-closed-groups", "shell")
	if got := hookDecision(t, out); got != "deny" {
		t.Fatalf("a flag parse error before -fail-closed-groups must still fail closed, got %q", got)
	}
}
