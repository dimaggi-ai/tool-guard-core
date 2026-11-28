package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

var permissionDecisionRe = regexp.MustCompile(`"permissionDecision":"([a-z]+)"`)

// hookVerdict runs the hook on one Bash call and returns its decision,
// "allow" when it prints none.
func hookVerdict(t *testing.T, cmd, cwd string, args ...string) string {
	t.Helper()
	ev, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": cmd},
		"cwd":             cwd,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := runHookStr(t, string(ev), args...)
	if m := permissionDecisionRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return "allow"
}

// TestReview090fZshOperatorsKeepTheBashReading: the write operators of zsh
// and fish do not change what the policy classifiers see. bash reads
// `rm >? -rf /` as `rm -rf /` with its output in a file named ?, and runs
// it. Each form must get the verdict of the same command written with the
// bash operator and a quoted target, the verdict of 22ed838.
func TestReview090fZshOperatorsKeepTheBashReading(t *testing.T) {
	policies := ".." + "/" + ".." + "/policies"
	floor := policies + "/irreversibility_floor.yaml"
	home := t.TempDir()
	t.Setenv("HOME", home)
	flagSets := []struct {
		name string
		args []string
		want string
	}{
		{"policy-dir", []string{"-policy-dir", policies, "-mode", "enforcement", "-fail-closed", "-escalate-as", "deny"}, "deny"},
		{"irreversibility floor", []string{"-policy", floor, "-mode", "enforcement", "-fail-closed"}, "ask"},
	}
	// Each zsh or fish operator with its bash reading: the bash operator
	// and the rest of the text as the file name.
	ops := []struct{ zsh, bash string }{
		{">?", `> '?'`},
		{">!", `> '!'`},
		{">>!", `>> '!'`},
		{"&>!", `&> '!'`},
		{"&>>!", `&>> '!'`},
	}
	bases := []string{"rm %s -rf /", "sudo rm %s -rf /usr", "rm%s -rf /", "dd if=/dev/zero %s of=/dev/sda"}
	for _, fs := range flagSets {
		for _, op := range ops {
			for _, b := range bases {
				zcmd := strings.Replace(b, "%s", op.zsh, 1)
				bcmd := strings.Replace(b, "%s", op.bash, 1)
				z := hookVerdict(t, zcmd, home, fs.args...)
				bv := hookVerdict(t, bcmd, home, fs.args...)
				if z != bv {
					t.Errorf("%s: %q gives %s, its bash reading %q gives %s", fs.name, zcmd, z, bcmd, bv)
				}
				if z != fs.want {
					t.Errorf("%s: %q gives %s, want %s", fs.name, zcmd, z, fs.want)
				}
			}
		}
	}
}

// TestReview090fApplyPatchAliasKeysKeepTheDeny: 22ed838 read the patch text
// only under command, input and patch. Under any other key it checked the
// call unchanged, and a write policy denied it. On a per-file envelope it
// dropped only command and input, so a shell policy read the patch under
// cmd, CommandLine or script as a command. Both checks stay, next to the
// check of each file the patch names.
func TestReview090fApplyPatchAliasKeysKeepTheDeny(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prot := home + "/.claude/settings.json"
	coding := []string{"-policy-dir", ".." + "/" + ".." + "/examples/coding-agent-guard/policies",
		"-mode", "enforcement", "-fail-closed", "-protect-path", prot}
	shipped := []string{"-policy-dir", ".." + "/" + ".." + "/policies", "-mode", "enforcement", "-fail-closed"}
	patch := "*** Begin Patch\n*** Update File: src/a.go\n@@\n-a\n+b\n*** End Patch"
	verdict := func(key string, args []string) string {
		ev, _ := json.Marshal(map[string]interface{}{
			"hook_event_name": "PreToolUse",
			"tool_name":       "apply_patch",
			"tool_input":      map[string]string{key: patch},
			"cwd":             home,
		})
		out, _ := runHookStr(t, string(ev), args...)
		if m := permissionDecisionRe.FindStringSubmatch(out); m != nil {
			return m[1]
		}
		return "allow"
	}
	for _, key := range []string{"diff", "text", "body", "content", "args", "patch_text", "changes"} {
		if got := verdict(key, coding); got != "deny" {
			t.Errorf("coding-agent policies, the patch under %q: %s, want deny as in 22ed838", key, got)
		}
	}
	// On macOS the temporary directory is under /var/, a path that
	// coding_agent_writes.yaml denies: 22ed838 denies the call there too.
	want := "ask"
	if strings.HasPrefix(home, "/var/") {
		want = "deny"
	}
	for _, key := range []string{"cmd", "CommandLine", "script"} {
		if got := verdict(key, shipped); got != want {
			t.Errorf("shipped policies, the patch under %q: %s, want %s as in 22ed838", key, got, want)
		}
		deny := append(append([]string{}, shipped...), "-escalate-as", "deny")
		if got := verdict(key, deny); got != "deny" {
			t.Errorf("shipped policies with -escalate-as deny, the patch under %q: %s, want deny as in 22ed838", key, got)
		}
	}
}

// TestReview090fDispatchMalformedShellCommandKeepsTheDeny: with -dispatch and
// -fail-closed, 22ed838 denied a shell tool other than Bash whose command is
// not a string, as a call it could not evaluate. That deny stays.
func TestReview090fDispatchMalformedShellCommandKeepsTheDeny(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	args := []string{"-policy-dir", ".." + "/" + ".." + "/policies", "-mode", "enforcement", "-fail-closed", "-dispatch", "gh_read"}
	inputs := []string{`{"command":5}`, `{"command":null}`, `{"cmd":5}`, `{"command":{"a":1}}`}
	for _, tool := range []string{"run_command", "shell", "run_terminal_cmd", "execute_command"} {
		for _, input := range inputs {
			ev := `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + input + `}`
			out, _ := runHookStr(t, ev, args...)
			got := "allow"
			if m := permissionDecisionRe.FindStringSubmatch(out); m != nil {
				got = m[1]
			}
			if got != "deny" {
				t.Errorf("%s with %s: %s, want deny as in 22ed838", tool, input, got)
			}
		}
	}
}
