package main

import (
	"strings"
	"testing"
)

// Tests for the post-review hardening of the fail-closed contract: an
// UNATTRIBUTABLE stdin error (malformed / oversized) must fail CLOSED when any
// fail-closed mode is engaged — an unparseable PreToolUse payload can't be
// proven non-destructive. Pure default still fails open.

func TestHook_MalformedStdin_FailClosedTools_Denies(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	out, code := runHookStr(t, "{ this is not json", "-policy", pol, "-fail-closed-tools", "bash,write")
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("malformed stdin + -fail-closed-tools should DENY (unattributable), got %q", d)
	}
}

func TestHook_MalformedStdin_GlobalFailClosed_Denies(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	out, _ := runHookStr(t, "not json at all", "-policy", pol, "-fail-closed")
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("malformed stdin + -fail-closed should DENY, got %q", d)
	}
}

func TestHook_MalformedStdin_Default_FailsOpen(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	out, _ := runHookStr(t, "}{ broken", "-policy", pol)
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("malformed stdin with no fail-closed flag should fail OPEN, got %q", d)
	}
}

func TestHook_OversizedStdin_FailClosed_Denies(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	big := "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"" + strings.Repeat("a", (1<<20)+16) + "\"}}"
	out, _ := runHookStr(t, big, "-policy", pol, "-fail-closed")
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("oversized stdin + -fail-closed should DENY, got %q", d)
	}
}

func TestHook_OversizedStdin_Default_FailsOpen(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	big := "{\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"" + strings.Repeat("a", (1<<20)+16) + "\"}}"
	out, _ := runHookStr(t, big, "-policy", pol)
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("oversized stdin with no fail-closed flag should fail OPEN, got %q", d)
	}
}

// The hook must forward the FULL tool_input, so a protected-path write hidden
// in an array param (not the flat file_path/path) is still caught.
func TestHook_ProtectPaths_ArrayParam(t *testing.T) {
	pol := writeHookPolicy(t, hookAllowPolicy)
	dir := t.TempDir()
	in := `{"tool_name":"multiedit","tool_input":{"paths":["` + dir + `/ok.txt","` + dir + `/secret.key"]}}`
	out, _ := runHookStr(t, in, "-policy", pol, "-protect-paths", dir+"/secret.key")
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("array-of-paths write to a protected path should DENY, got %q", d)
	}
}
