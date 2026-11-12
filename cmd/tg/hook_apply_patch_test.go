package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func applyPatchDecision(t *testing.T, args []string, toolInput map[string]interface{}, cwd string) (string, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{
		"tool_name": "apply_patch", "tool_input": toolInput, "cwd": cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := runHook(args, bytes.NewReader(payload), &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	return hookDecisionReason(t, buf.String())
}

// TestApplyPatchTargets: every line that names a file gives a target, also
// with white space before the marker, with CRLF line ends, and outside a
// well-formed patch. A line the patch adds does not.
func TestApplyPatchTargets(t *testing.T) {
	text := strings.Join([]string{
		"*** Begin Patch",
		"*** Add File: a.txt",
		"+one",
		"+*** Delete File: not-a-target",
		"  *** Update File: dir/b.txt  ",
		"*** Move to: c.txt\r",
		"@@",
		"-old",
		"+two",
		"\t*** Delete File: /abs/d.txt",
		"*** Add File: a.txt",
		"*** End Patch",
	}, "\n")
	targets, added := applyPatchTargets(text)
	if got, want := strings.Join(targets, "|"), "a.txt|dir/b.txt|c.txt|/abs/d.txt"; got != want {
		t.Errorf("targets %q, want %q", got, want)
	}
	if want := "one\n*** Delete File: not-a-target\ntwo"; added != want {
		t.Errorf("added %q, want %q", added, want)
	}
	if targets, _ := applyPatchTargets("*** Begin Patch\n*** End Patch"); len(targets) != 0 {
		t.Errorf("a patch without a file gave targets %v", targets)
	}
}

// TestApplyPatchIsReadPerFile runs apply_patch calls through the hook with the
// shipped policies and a protected path.
func TestApplyPatchIsReadPerFile(t *testing.T) {
	policies := filepath.Join("..", "..", "policies")
	args := []string{"-policy-dir", policies, "-mode", "enforcement", "-protect-paths", "/w/.codex/hooks.json,/w/.tool-guard"}
	p := func(lines ...string) string {
		return "*** Begin Patch\n" + strings.Join(lines, "\n") + "\n*** End Patch"
	}
	many := func(n int) string {
		var l []string
		for i := 0; i < n; i++ {
			l = append(l, fmt.Sprintf("*** Add File: f%d.txt", i), "+x")
		}
		return p(l...)
	}
	cases := []struct {
		name  string
		input map[string]interface{}
		cwd   string
		want  string
		cites string
	}{
		{"new file in the working tree", map[string]interface{}{"command": p("*** Add File: a.txt", "+x")}, "/w", "allow", ""},
		{"the parameter input", map[string]interface{}{"input": p("*** Add File: a.txt", "+x")}, "/w", "allow", ""},
		{"the parameter patch", map[string]interface{}{"patch": p("*** Add File: a.txt", "+x")}, "/w", "allow", ""},
		{"a list of strings", map[string]interface{}{"command": []string{"apply_patch", p("*** Add File: a.txt", "+x")}}, "/w", "allow", ""},
		{"64 files", map[string]interface{}{"command": many(64)}, "/w", "allow", ""},
		{"65 files", map[string]interface{}{"command": many(65)}, "/w", "deny", "at most 64"},
		{"relative protected file", map[string]interface{}{"command": p("*** Update File: .codex/hooks.json", "@@", "+x")}, "/w", "deny", "protected path"},
		{"absolute protected file", map[string]interface{}{"command": p("*** Delete File: /w/.codex/hooks.json")}, "/elsewhere", "deny", "protected path"},
		{"dot-dot to a protected file", map[string]interface{}{"command": p("*** Add File: sub/../.tool-guard/protect-paths", "+x")}, "/w", "deny", "protected path"},
		{"move onto a protected file", map[string]interface{}{"command": p("*** Update File: a.txt", "*** Move to: .codex/hooks.json", "@@", "+x")}, "/w", "deny", "protected path"},
		{"second file protected", map[string]interface{}{"command": p("*** Add File: a.txt", "+x", "*** Delete File: .codex/hooks.json")}, "/w", "deny", "protected path"},
		{"marker after white space", map[string]interface{}{"command": p("   *** Update File: .codex/hooks.json", "@@", "+x")}, "/w", "deny", "protected path"},
		{"protected file in a second parameter", map[string]interface{}{"command": p("*** Add File: a.txt", "+x"), "input": p("*** Delete File: .codex/hooks.json")}, "/w", "deny", "protected path"},
		{"system path", map[string]interface{}{"command": p("*** Update File: /etc/hosts", "@@", "+x")}, "/w", "deny", "confined to the working tree"},
		{"private key in the added lines", map[string]interface{}{"command": p("*** Add File: id.txt", "+-----BEGIN OPENSSH PRIVATE KEY-----")}, "/w", "deny", "confined to the working tree"},
		{"relative path under a system directory", map[string]interface{}{"command": p("*** Update File: hosts", "@@", "+x")}, "/etc", "deny", "confined to the working tree"},
		{"empty path", map[string]interface{}{"command": p("*** Add File:   ", "+x")}, "/w", "deny", "empty path"},
		{"no file in the text", map[string]interface{}{"command": "*** Begin Patch\n*** End Patch"}, "/w", "deny", "confined to the working tree"},
		{"text is not a string", map[string]interface{}{"command": 7}, "/w", "deny", "confined to the working tree"},
		{"no cwd, relative protected name", map[string]interface{}{"command": p("*** Add File: policies/x.yaml", "+x")}, "", "deny", ""},
	}
	for _, c := range cases {
		dec, reason := applyPatchDecision(t, args, c.input, c.cwd)
		if dec != c.want || (c.cites != "" && !strings.Contains(reason, c.cites)) {
			t.Errorf("%s: decision %q reason %q, want %q citing %q", c.name, dec, reason, c.want, c.cites)
		}
	}
}

// TestApplyPatchProtectedPathWithoutPolicy: the protected-path check reads the
// files of a patch also when no write policy is loaded.
func TestApplyPatchProtectedPathWithoutPolicy(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-policy-dir", dir, "-mode", "enforcement", "-protect-paths", "/w/.codex/hooks.json"}
	text := "*** Begin Patch\n*** Update File: .codex/hooks.json\n@@\n+x\n*** End Patch"
	dec, reason := applyPatchDecision(t, args, map[string]interface{}{"command": text}, "/w")
	if dec != "deny" || !strings.Contains(reason, "protected path") {
		t.Errorf("decision %q reason %q, want deny by the protected-path check", dec, reason)
	}
}
