package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hookBashStdin builds a PreToolUse payload for a Bash command.
func hookBashStdin(t *testing.T, command string) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// hookMaybeDecision returns "" when the hook wrote no permissionDecision.
func hookMaybeDecision(t *testing.T, output string) string {
	t.Helper()
	if strings.TrimSpace(output) == "" {
		return ""
	}
	return hookDecision(t, output)
}

func TestHookDispatch_ClassifiesAllowedBash(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	for _, tc := range []struct{ command, want string }{
		{"gh pr list", "allow"},
		{"gh issue view 75", "allow"},
		{"gh pr view 12 --json title | jq .title", "allow"},
		{"pwd", ""},
		{"ls -la docs", ""},
		{"python3 script.py", "ask"},
		{"go test ./...", "ask"},
		{"git push", "ask"},
		{"gh pr create --fill", "ask"},
		{"'gh' pr create --fill", "ask"},
		{"g''h pr create --fill", "ask"},
		{"g\\h pr create --fill", "ask"},
		{"gh 'pr' create --fill", "ask"},
		{"sh -c 'g'\"h\"' pr create --fill'", "ask"},
		{"x=gh; \"$x\" pr create --fill", "ask"},
		{"$(printf gh) pr create --fill", "ask"},
		{"gh api repos/o/r/pulls", "ask"},
		{"gh --hostname h.example pr list", "ask"},
		{"ls $d", "ask"},
		{"pwd; git push", "ask"},
		{"rm -rf /tmp/x", "deny"},               // an enforcing rule still denies
		{"gh pr list && rm -rf /tmp/x", "deny"}, // before any dispatch
	} {
		out, code := runHookStr(t, hookBashStdin(t, tc.command), "-policy", pol, "-dispatch", "gh_read")
		if code != 0 {
			t.Fatalf("%q: exit %d", tc.command, code)
		}
		if got := hookMaybeDecision(t, out); got != tc.want {
			t.Errorf("%q: decision %q, want %q; output=%s", tc.command, got, tc.want, out)
		}
	}
}

func TestHookDispatch_EscalateRuleOutranksVerifiedRead(t *testing.T) {
	pol := writeHookPolicy(t, `policy_id: forge
name: forge
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash]
rules:
  - rule_id: escalate-gh
    conditions: {field: parameters.command, operator: regex, value: 'gh '}
    effect: escalate
    citation: {document_id: d, excerpt: "forge"}
`)
	out, _ := runHookStr(t, hookBashStdin(t, "gh pr list"), "-policy", pol, "-dispatch", "gh_read")
	if d := hookDecision(t, out); d != "ask" {
		t.Errorf("a loaded escalate rule must still ask, got %q", d)
	}
}

func TestHookDispatch_ProtectedPathDeniesFirst(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	stdin := `{"tool_name":"Bash","tool_input":{"command":"ls > /protected/x"}}`
	out, _ := runHookStr(t, stdin, "-policy", pol, "-dispatch", "gh_read", "-protect-path", "/protected")
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("protected path must deny, got %q", d)
	}
}

func TestHookDispatch_OtherToolsUnchanged(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	out, _ := runHookStr(t, `{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}`, "-policy", pol, "-dispatch", "gh_read")
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("a non-Bash tool keeps the engine decision, got %q", d)
	}
}

func TestHookDispatch_MissingCommandAsks(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	for _, stdin := range []string{`{"tool_name":"Bash","tool_input":{}}`, `{"tool_name":"Bash","tool_input":{"command":7}}`} {
		out, _ := runHookStr(t, stdin, "-policy", pol, "-dispatch", "gh_read")
		if d := hookDecision(t, out); d != "ask" {
			t.Errorf("%s: want ask, got %q", stdin, d)
		}
	}
}

func TestHookDispatch_FailuresDeny(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("policy_id: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ls := hookBashStdin(t, "ls")
	for name, tc := range map[string]struct {
		stdin string
		args  []string
	}{
		"malformed JSON":     {"{not json", []string{"-policy", pol, "-dispatch", "gh_read"}},
		"no policy":          {ls, []string{"-dispatch", "gh_read"}},
		"policy load error":  {ls, []string{"-policy", bad, "-dispatch", "gh_read"}},
		"unknown profile":    {ls, []string{"-policy", pol, "-dispatch", "all"}},
		"shadow mode":        {ls, []string{"-policy", pol, "-dispatch", "gh_read", "-mode", "shadow"}},
		"flag error first":   {ls, []string{"-bogus", "-policy", pol, "-dispatch", "gh_read"}},
		"read tool, no load": {`{"tool_name":"Read","tool_input":{}}`, []string{"-dispatch", "gh_read"}},
	} {
		out, code := runHookStr(t, tc.stdin, tc.args...)
		if code != 0 {
			t.Errorf("%s: exit %d", name, code)
		}
		if d := hookMaybeDecision(t, out); d != "deny" {
			t.Errorf("%s: want deny, got %q; output=%s", name, d, out)
		}
	}
}

func TestHookDispatchRequested(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"-dispatch", "gh_read"}, true},
		{[]string{"--dispatch=gh_read"}, true},
		{[]string{"-policy", "p", "-dispatch="}, true},
		{[]string{"-policy", "dispatch"}, false},
		{[]string{"-dispatcher"}, false},
		{nil, false},
	} {
		if got := hookDispatchRequested(tc.args); got != tc.want {
			t.Errorf("hookDispatchRequested(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestHookSupervisorHelperProcess is the child for supervisor tests. It does
// nothing unless TG_HOOK_HELPER selects a behavior.
func TestHookSupervisorHelperProcess(t *testing.T) {
	mode := os.Getenv("TG_HOOK_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "real":
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("TG_HOOK_HELPER_ARGS")), &args); err != nil {
			os.Exit(3)
		}
		os.Exit(runHook(args, os.Stdin, os.Stdout))
	case "allow":
		emitHookDecisionTo(os.Stdout, "allow", "ok")
	case "nodecision":
		emitHookDecisionTo(os.Stdout, hookNoDecision, "unrelated")
	case "garbage":
		fmt.Fprint(os.Stdout, "not json")
	case "empty":
	case "two":
		emitHookDecisionTo(os.Stdout, "allow", "")
		emitHookDecisionTo(os.Stdout, "allow", "")
	case "unknown-decision":
		fmt.Fprint(os.Stdout, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}`)
	case "extra-field":
		fmt.Fprint(os.Stdout, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"continue":true}`)
	case "wrong-event":
		fmt.Fprint(os.Stdout, `{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"allow"}}`)
	case "huge":
		fmt.Fprint(os.Stdout, strings.Repeat("x", maxHookChildStdout+1))
	case "exit1":
		emitHookDecisionTo(os.Stdout, "allow", "")
		os.Exit(1)
	case "panic":
		panic("helper crash")
	case "sleep":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func helperChild(t *testing.T, mode string, args ...string) func(context.Context) *exec.Cmd {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context) *exec.Cmd {
		c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHookSupervisorHelperProcess$")
		c.Env = append(os.Environ(), "TG_HOOK_HELPER="+mode, "TG_HOOK_HELPER_ARGS="+string(encoded))
		return c
	}
}

func superviseStr(t *testing.T, stdin string, timeout time.Duration, child func(context.Context) *exec.Cmd) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := superviseHook(strings.NewReader(stdin), &out, &errOut, timeout, child); code != 0 {
		t.Fatalf("supervisor exit %d", code)
	}
	return out.String()
}

func TestHookSupervisor_TrustsOnlyWellFormedChildOutput(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"allow", "allow"},
		{"nodecision", ""},
		{"garbage", "deny"},
		{"empty", "deny"},
		{"two", "deny"},
		{"unknown-decision", "deny"},
		{"extra-field", "deny"},
		{"wrong-event", "deny"},
		{"huge", "deny"},
		{"exit1", "deny"},
		{"panic", "deny"},
	} {
		out := superviseStr(t, `{}`, 30*time.Second, helperChild(t, tc.mode))
		if got := hookMaybeDecision(t, out); got != tc.want {
			t.Errorf("%s: decision %q, want %q; output=%s", tc.mode, got, tc.want, out)
		}
		if tc.want == "" && out != "" {
			t.Errorf("%s: no-decision must write nothing, wrote %q", tc.mode, out)
		}
	}
}

func TestHookSupervisor_TimeoutDenies(t *testing.T) {
	start := time.Now()
	out := superviseStr(t, `{}`, 500*time.Millisecond, helperChild(t, "sleep"))
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("timeout: want deny, got %q", d)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("supervisor took %s after a 500ms timeout", elapsed)
	}
}

func TestHookSupervisor_UnavailableChildDenies(t *testing.T) {
	out := superviseStr(t, `{}`, time.Second, func(context.Context) *exec.Cmd { return nil })
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("want deny, got %q", d)
	}
}

func TestHookSupervisor_OversizedStdinDenies(t *testing.T) {
	out := superviseStr(t, strings.Repeat(" ", 1<<20+1), time.Second, helperChild(t, "allow"))
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("want deny, got %q", d)
	}
}

// The real child path: supervisor, child process, runHook and dispatcher.
func TestHookSupervisor_RealChildDispatch(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	args := []string{"-policy", pol, "-dispatch", "gh_read"}
	for _, tc := range []struct{ command, want string }{
		{"gh pr list", "allow"},
		{"pwd", ""},
		{"git push", "ask"},
		{"rm -rf /tmp/x", "deny"},
	} {
		out := superviseStr(t, hookBashStdin(t, tc.command), 30*time.Second, helperChild(t, "real", args...))
		if got := hookMaybeDecision(t, out); got != tc.want {
			t.Errorf("%q: decision %q, want %q; output=%s", tc.command, got, tc.want, out)
		}
	}
}
