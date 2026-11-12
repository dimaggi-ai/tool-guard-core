package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestHookReadsTheWorkDirectoryOfThePayload runs `tg hook` on payloads that
// name the directory of the call, and on the command keys it reads.
func TestHookReadsTheWorkDirectoryOfThePayload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs POSIX paths")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"prot", "proj", "pol"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-policy-dir", root + "/pol", "-protect-paths", root + "/prot"}
	deny := []string{
		`{"tool_name":"Bash","cwd":"` + root + `/proj","tool_input":{"command":"echo x > ../prot/f"}}`,
		`{"tool_name":"Write","cwd":"` + root + `/proj","tool_input":{"file_path":"../prot/f","content":"x"}}`,
		`{"tool_name":"shell","tool_input":{"command":"echo x > ../prot/f","workdir":"` + root + `/proj"}}`,
		`{"tool_name":"Bash","tool_input":{"Command":"echo x > ` + root + `/prot/f"}}`,
		`{"tool_name":"Bash","tool_input":{"COMMAND":"echo x > ` + root + `/prot/f"}}`,
		`{"tool_name":"FooBar","tool_input":{"bash_command":"echo x > ` + root + `/prot/f"}}`,
	}
	for _, payload := range deny {
		out, _ := runHookStr(t, payload, args...)
		if got := hookDecision(t, out); got != "deny" {
			t.Errorf("%s: decision %q, want deny", payload, got)
		}
	}
	allow := []string{
		`{"tool_name":"Bash","tool_input":{"command":"echo x > ../prot/f"}}`,
		`{"tool_name":"Bash","cwd":"` + root + `/proj","tool_input":{"command":"echo x > ../proj/f"}}`,
		`{"tool_name":"mcp__pg__query","tool_input":{"command":"SELECT * FROM t WHERE a > $1"}}`,
	}
	for _, payload := range allow {
		out, _ := runHookStr(t, payload, args...)
		if got := hookDecision(t, out); got == "deny" {
			t.Errorf("%s: denied: %s", payload, out)
		}
	}
	// The Antigravity form names the directory in the tool arguments.
	agy, _ := runHookStr(t, `{"toolCall":{"name":"run_command","args":{"CommandLine":"echo x > ../prot/f","Cwd":"`+root+`/proj"}}}`, args...)
	if !strings.Contains(agy, `"decision":"deny"`) {
		t.Errorf("the Antigravity form is not denied: %s", agy)
	}
}

// TestHookDeniesAPayloadWithTwoToolCalls: a payload with a toolCall object
// and tool_name or tool_input names two calls. The hook cannot know which
// one runs. The wrong type under any command key is denied in the same way
// as under "command", and the denial is in the audit log.
func TestHookDeniesAPayloadWithTwoToolCalls(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	closed := []string{"-policy-dir", dir, "-fail-closed-groups", "shell,filesystem_writes", "-audit-log", audit}
	for _, payload := range []string{
		`{"tool_name":"Read","tool_input":{"file_path":"a"},"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf x"}}}`,
		`{"tool_name":"Read","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf x"}}}`,
		`{"tool_input":{"command":"ls"},"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf x"}}}`,
	} {
		out, _ := runHookStr(t, payload, closed...)
		if !strings.Contains(out, "deny") || !strings.Contains(out, "toolCall") {
			t.Errorf("%s: not denied: %s", payload, out)
		}
	}
	for _, payload := range []string{
		`{"tool_name":"Bash","tool_input":{"Command":["rm","-rf","x"]}}`,
		`{"tool_name":"Bash","tool_input":{"command_line":7}}`,
		`{"tool_name":"Bash","tool_input":{"bash_command":{"a":1}}}`,
		`{"tool_name":"Bash","tool_input":{"shellCommand":["a"]}}`,
	} {
		out, _ := runHookStr(t, payload, closed...)
		if got := hookDecision(t, out); got != "deny" {
			t.Errorf("%s: decision %q, want deny", payload, got)
		}
	}
	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("the denials are not in the audit log: %v", err)
	}
	if n := strings.Count(string(raw), "\n"); n < 4 {
		t.Errorf("audit log has %d lines, want one for each of the 4 wrong-type denials", n)
	}
	if !strings.Contains(string(raw), "not a string") {
		t.Errorf("the audit log does not hold the reason: %s", raw)
	}
}
