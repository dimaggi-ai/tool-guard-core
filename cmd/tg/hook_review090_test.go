package main

// Regression tests for the protected-path and dispatch findings of the
// 0.9.0 pre-release review (2026-11-25). Each case was a call the shipped
// coding-agent policy allowed before the fix.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func review090Hook(t *testing.T, ev map[string]interface{}, protect string) string {
	t.Helper()
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join("..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_shell.yaml")
	args := []string{"-policy", pol, "-mode", "enforcement", "-fail-closed", "-protect-path", protect}
	var buf bytes.Buffer
	if code := runHook(args, bytes.NewReader(payload), &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	return hookMaybeDecision(t, buf.String())
}

func review090Tree(t *testing.T) (home, cdir, file string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc and symbolic links")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	cdir = filepath.Join(home, ".claude")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(cdir, "settings.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// lnk/.. is home/.claude physically and home lexically.
	if err := os.MkdirAll(filepath.Join(cdir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cdir, "sub"), filepath.Join(home, "lnk")); err != nil {
		t.Fatal(err)
	}
	return home, cdir, file
}

func bashEv(cmd, cwd string) map[string]interface{} {
	return map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]interface{}{"command": cmd}, "cwd": cwd}
}

func TestReview090ProtectedPathBypasses(t *testing.T) {
	home, cdir, file := review090Tree(t)
	patch := func(lines ...string) string {
		return "*** Begin Patch\n" + strings.Join(lines, "\n") + "\n*** End Patch"
	}
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// P1: a brace list in a redirect target.
		{"redirect {P,}", bashEv("echo x > {"+file+",}", home)},
		{"redirect P.{json,}", bashEv("echo x > "+cdir+"/settings.{json,}", home)},
		{"redirect {~/...,}", bashEv("echo x > {~/.claude/settings.json,}", home)},
		{"redirect through a link {P,}", bashEv("echo x > {"+home+"/lnk/../settings.json,}", home)},
		// P2: /proc and /dev/fd paths with empty, "." or ".." parts.
		{"/proc/self//cwd", bashEv("echo x > /proc/self//cwd/settings.json", cdir)},
		{"/proc/self/./cwd", bashEv("echo x > /proc/self/./cwd/settings.json", cdir)},
		{"/dev/fd/3//", bashEv("exec 3< "+cdir+" && echo x > /dev/fd/3//settings.json", "/tmp")},
		{"/dev/fd/../cwd", bashEv("echo x > /dev/fd/../cwd/settings.json", cdir)},
		{"Write /proc/self//cwd", map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": cdir,
			"tool_input": map[string]interface{}{"file_path": "/proc/self//cwd/settings.json", "content": "x"}}},
		{"Write /proc/self/./cwd", map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": cdir,
			"tool_input": map[string]interface{}{"file_path": "/proc/self/./cwd/settings.json", "content": "x"}}},
		// P3: an apply_patch target with ".." after a link.
		{"apply_patch lnk/../settings.json", map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": home,
			"tool_input": map[string]interface{}{"command": patch("*** Update File: lnk/../settings.json", "@@", "+x")}}},
		{"apply_patch Move to lnk/../settings.json", map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": home,
			"tool_input": map[string]interface{}{"command": patch("*** Update File: a.txt", "*** Move to: lnk/../settings.json", "@@", "+x")}}},
		// P4: the patch text under an alias key.
		{"apply_patch cmd alias", map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": home,
			"tool_input": map[string]interface{}{"command": patch("*** Add File: safe.txt", "+ok"), "cmd": patch("*** Update File: "+file, "@@", "+x")}}},
		// P5: a command in a shell option.
		{"fish -c --init-command=", bashEv("fish -c --init-command='rm "+file+"' 'cat "+file+"'", home)},
		{"fish -c CMD --init-command", bashEv("fish -c 'cat "+file+"' --init-command 'rm "+file+"'", home)},
		{"bash -c -i", bashEv("bash -c -i 'cat "+file+"'", home)},
		// P6: a long brace list after a glued option, after "=", and after a link.
		{"tar -cfP.{json,{1..70}}", bashEv("tar -cf"+cdir+"/settings.{json,{1..70}} /etc/hosts", home)},
		{"out=P.{json,{1..70}}", bashEv("python3 w.py out="+cdir+"/settings.{json,{1..70}}", home)},
		{"lnk/../P.{json,{1..70}}", bashEv("python3 w.py "+home+"/lnk/../settings.{json,{1..70}}", home)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := review090Hook(t, c.ev, file); got != "deny" {
				t.Errorf("decision %q, want deny", got)
			}
		})
	}
	// A plain dir/../dir with a long list is still read.
	t.Run("free/../free long brace list", func(t *testing.T) {
		free := filepath.Join(home, "free")
		if err := os.MkdirAll(free, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := review090Hook(t, bashEv("cat "+free+"/../free/set.{json,{1..70}}", home), file); got == "deny" {
			t.Errorf("decision deny, want not deny")
		}
	})
}

func review090AgyHook(t *testing.T, ev map[string]interface{}, protect string) string {
	t.Helper()
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join("..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_shell.yaml")
	args := []string{"-policy", pol, "-mode", "enforcement", "-fail-closed", "-protect-path", protect, "-dialect", "antigravity", "-dispatch", "gh_read"}
	var buf bytes.Buffer
	if code := runHook(args, bytes.NewReader(payload), &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var out struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, buf.String())
	}
	return out.Decision
}

// P7: dispatch applies to the shell tool names of every dialect.
func TestReview090DispatchShellToolNames(t *testing.T) {
	_, _, file := review090Tree(t)
	agy := func(cmd string) map[string]interface{} {
		return map[string]interface{}{"toolCall": map[string]interface{}{"name": "run_command", "args": map[string]interface{}{"CommandLine": cmd}}}
	}
	for _, c := range []struct{ cmd, want string }{
		{"echo hello", "force_ask"},
		{"gh pr list", "allow"},
	} {
		if got := review090AgyHook(t, agy(c.cmd), file); got != c.want {
			t.Errorf("antigravity run_command %q: decision %q, want %q", c.cmd, got, c.want)
		}
	}
}

// P8: with -escalate-as deny the audit record says the call was denied.
func TestReview090EscalateAsDenyAudit(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out, _ := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", "deny", "-audit-log", auditPath)
	if got := hookDecision(t, out); got != "deny" {
		t.Fatalf("decision %q, want deny", got)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var trace domain.DecisionTrace
	if err := json.Unmarshal(bytes.TrimSpace(raw), &trace); err != nil {
		t.Fatal(err)
	}
	if trace.ActionTaken != domain.ActionDenied {
		t.Errorf("audit action %q, want %q", trace.ActionTaken, domain.ActionDenied)
	}
	if !strings.Contains(trace.DecisionReason, "-escalate-as deny") {
		t.Errorf("audit reason %q does not say the escalation was converted", trace.DecisionReason)
	}
	if ok, err := audit.VerifyCanonicalTraceHash(&trace); err != nil || !ok {
		t.Errorf("audit hash invalid: ok=%v err=%v", ok, err)
	}
}
