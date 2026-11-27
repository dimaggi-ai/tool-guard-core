package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// patchVerdict runs the hook on one apply_patch call and returns its
// decision, "allow" when it prints none, and the reason.
func patchVerdict(t *testing.T, input map[string]interface{}, cwd string, args ...string) (string, string, time.Duration) {
	t.Helper()
	ev, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"tool_name":       "apply_patch",
		"tool_input":      input,
		"cwd":             cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, _ := runHookStr(t, string(ev), args...)
	took := time.Since(start)
	dec := "allow"
	if m := permissionDecisionRe.FindStringSubmatch(out); m != nil {
		dec = m[1]
	}
	return dec, out, took
}

// TestReview090gApplyPatchDotDotKeepsTheContextFileRule: 22ed838 joined a
// relative apply_patch target to cwd with path.Join, which removes DIR/..,
// and the context-file rule matched the cleaned path. Each target keeps the
// deny of 22ed838.
func TestReview090gApplyPatchDotDotKeepsTheContextFileRule(t *testing.T) {
	work := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	for _, d := range []string{".claude/commands", ".github/workflows", ".cursor/rules"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-policy-dir", ".." + "/" + ".." + "/policies", "-mode", "enforcement", "-fail-closed", "-escalate-as", "deny"}
	targets := []string{
		".claude/commands/../settings.json",
		".claude/nodir/../settings.json",
		".claude/commands/../settings.local.json",
		".github/workflows/../copilot-instructions.md",
		".github/nodir/../copilot-instructions.md",
		".cursor/rules/../mcp.json",
	}
	for _, target := range targets {
		for _, key := range []string{"command", "input", "patch"} {
			patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch"
			if got, out, _ := patchVerdict(t, map[string]interface{}{key: patch}, work, args...); got != "deny" {
				t.Errorf("%s under %q: %s, want deny as in 22ed838\n%s", target, key, got, out)
			}
		}
	}
}

// TestReview090gApplyPatchManyWorkDirsEndsInTime: one apply_patch call with
// thousands of work-directory keys took minutes and gigabytes. The hook reads
// at most maxApplyPatchWorkDirs of them and denies a call with more, and it
// answers within 10 s, the time a -dispatch parent waits for its child.
func TestReview090gApplyPatchManyWorkDirsEndsInTime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prot := filepath.Join(home, ".claude", "settings.json")
	args := []string{"-policy", ".." + "/" + ".." + "/examples/coding-agent-guard/policies/coding_agent_shell.yaml",
		"-mode", "enforcement", "-fail-closed", "-protect-path", prot}
	patch := func(files ...string) string {
		var b strings.Builder
		b.WriteString("*** Begin Patch\n")
		for _, f := range files {
			b.WriteString("*** Add File: " + f + "\n+x\n")
		}
		b.WriteString("*** End Patch")
		return b.String()
	}
	files := func(n int) []string {
		var fs []string
		for i := 0; i < n; i++ {
			fs = append(fs, fmt.Sprintf("f%d", i))
		}
		return fs
	}
	keyed := func(n int, ps string) map[string]interface{} {
		in := map[string]interface{}{"command": ps}
		for i := 0; i < n; i++ {
			in[fmt.Sprintf("a%d", i)] = map[string]string{"workdir": fmt.Sprintf("d%d", i)}
		}
		return in
	}
	listed := func(n int, ps string) map[string]interface{} {
		var l []map[string]string
		for i := 0; i < n; i++ {
			l = append(l, map[string]string{"cwd": fmt.Sprintf("d%d", i)})
		}
		return map[string]interface{}{"command": ps, "dirs": l}
	}
	cases := []struct {
		name  string
		input map[string]interface{}
		want  string
	}{
		{"1 file, 2000 workdir keys", keyed(2000, patch("f0")), "deny"},
		{"1 file, 3000 workdir keys", keyed(3000, patch("f0")), "deny"},
		{"60 files, 300 workdir keys", keyed(300, patch(files(60)...)), "deny"},
		{"60 files, a list of 1000 cwd keys", listed(1000, patch(files(60)...)), "deny"},
		{"protected file last of 2, 2000 workdir keys", keyed(2000, patch("f0", ".claude/settings.json")), "deny"},
		{"64 files, 8 workdir keys", keyed(8, patch(files(64)...)), "allow"},
		{"protected file through the 8th workdir key", func() map[string]interface{} {
			in := keyed(7, patch("settings.json"))
			in["zz"] = map[string]string{"workdir": ".claude"}
			return in
		}(), "deny"},
	}
	for _, c := range cases {
		got, out, took := patchVerdict(t, c.input, home, args...)
		if got != c.want {
			t.Errorf("%s: %s, want %s\n%s", c.name, got, c.want, out)
		}
		if took > 10*time.Second+500*time.Millisecond {
			t.Errorf("%s: took %s, want the answer within 10 s", c.name, took)
		}
	}
}

// TestReview090gHookCallBudgetDenies: past hookCallBudget the hook denies,
// whatever the evaluation is still doing. Here the input never ends.
func TestReview090gHookCallBudgetDenies(t *testing.T) {
	old := hookCallBudget
	hookCallBudget = 200 * time.Millisecond
	defer func() { hookCallBudget = old }()
	r, w := io.Pipe()
	defer w.Close()
	var out strings.Builder
	start := time.Now()
	code := runHook([]string{"-policy-dir", ".." + "/" + ".." + "/policies"}, r, &out)
	took := time.Since(start)
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if m := permissionDecisionRe.FindStringSubmatch(out.String()); m == nil || m[1] != "deny" {
		t.Errorf("decision %q, want deny", out.String())
	}
	if !strings.Contains(out.String(), "did not end in") {
		t.Errorf("reason %q does not name the time limit", out.String())
	}
	if took > 2*time.Second {
		t.Errorf("took %s, want about the 200ms budget", took)
	}
}
