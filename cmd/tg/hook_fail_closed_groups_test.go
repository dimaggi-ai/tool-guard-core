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

// TestHookDeniesAToolInputItCannotRead: a tool input that is not an object,
// or a command that is not a string, got an empty parameter object and the
// call was allowed with the fail-closed flags set.
func TestHookDeniesAToolInputItCannotRead(t *testing.T) {
	dir := t.TempDir()
	closed := []string{"-policy-dir", dir, "-fail-closed-groups", "shell,filesystem_writes"}
	for _, payload := range []string{
		`{"tool_name":"Bash","tool_input":"rm -rf /"}`,
		`{"tool_name":"Bash","tool_input":["rm","-rf","/"]}`,
		`{"tool_name":"shell","tool_input":{"command":["rm","-rf","/"]}}`,
		`{"tool_name":"Bash","tool_input":{"command":{"x":1}}}`,
		`{"tool_name":"FooBar","tool_input":{"script":7}}`,
		`{"tool_name":"Write","tool_input":"x"}`,
	} {
		out, _ := runHookStr(t, payload, closed...)
		if got := hookDecision(t, out); got != "deny" {
			t.Errorf("%s: decision %q, want deny", payload, got)
		}
		if !strings.Contains(out, "not a") {
			t.Errorf("%s: the reason does not say what is wrong: %s", payload, out)
		}
	}
	// The Antigravity form answers with a top-level decision.
	agy, _ := runHookStr(t, `{"toolCall":{"name":"run_command","args":{"CommandLine":["rm","-rf","/"]}}}`, closed...)
	if !strings.Contains(agy, `"decision":"deny"`) || !strings.Contains(agy, "not a string") {
		t.Errorf("the Antigravity form is not denied: %s", agy)
	}
	// A tool in a group that is not listed keeps the open default.
	out, _ := runHookStr(t, `{"tool_name":"Read","tool_input":"x"}`, closed...)
	if got := hookDecision(t, out); got == "deny" {
		t.Errorf("Read with a string input was denied: %s", out)
	}
	// A string command is not touched by this check.
	if why := hookInputMalformed(hookInput{ToolInput: []byte(`{"command":"ls","timeout":5}`)}); why != "" {
		t.Errorf("a well-formed input is reported as %q", why)
	}
}

// TestDocsNameTheLinkAndUnknownToolRules pins the sentences that state the
// rules of TestDotDotAfterALinkIsFollowed and TestShellGroupToolGetsTheShellCheck
// (pkg/engine) and runs the example hook on the forms they name.
func TestDocsNameTheLinkAndUnknownToolRules(t *testing.T) {
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	requireSentences(t, readme,
		"A word that holds `/proc/NAME/cwd` counts in the same way, and a redirection to such a word is denied.",
		"The hook follows symbolic links, also a link that stands before `..`.",
		"A write tool path is read in the same way.",
		"A tool name that `tg hook` does not know is treated as a shell tool: the shell policies read its `command`.",
		"They deny the call only when the text names a protected path, because the command of such a tool can be text in another language.",
		"It does not read a command under another key, such as `input` or `args`.",
		"The same is true for a word that holds `/dev/fd/N/` or `/proc/NAME/fd/N/` before a file name.",
		"The hook denies a command that makes a link to a protected path or to a directory above one, and that also runs a program that is not read-only or writes with a redirection, as in `ln -s ~/.claude l && echo x > l/settings.json`.",
		"A word that holds `/proc/NAME/root` counts in the same way.",
		"The hook does not expand a brace list that makes more than 64 words.",
		"When the comma lists of one word make more than 4096 words, the word counts as the name of a protected path.",
		"The same is true for an `ln` in a text that the command runs or can run: the argument of `bash -c`, the words of `eval`, a command substitution, a quoted word, and the words after `echo` or `printf`.",
		"It is also true for an `ln` after `busybox`, after `xargs`, and after a program that is not read-only, as in `flock FILE ln -s ~/.claude l && echo x > l/settings.json`.",
		"A link to `/dev/fd` or to a path under `/proc` counts as a link to a protected path.",
		"The hook does not see an `ln` that runs under another name, such as an alias or a copy of the program.",
		"A link that `ln` makes with a word from a variable or from a command substitution counts in the same way, as in `c=\"ln -s $HOME l\"; $c`, because the hook cannot read the target.",
		"It also does not see an `ln` that the command builds from parts: from more than one variable, as in `x=ln; y=-s; z=$HOME; $x $y $z l`, with a separator other than a space (`IFS=,`), with a default value (`${x:-ln -s $HOME l}`), with `printf -v`, or with a change of the text of a variable (`${c//X/}`).",
		"The hook also denies a command that makes a link with `ln`, holds `..` after the name of the link, and runs a program that is not read-only or writes with a redirection, as in `ln -s ~/proj l && echo x > l/../.claude/settings.json`.",
		"The same is true when one word holds the name of the link and another word holds `..`, as in `cd l/sub && echo x > ../../f`.",
		"The hook also denies such a command when no other program writes and the command runs `ln` two times or more, as in `ln -s ~/proj l && ln -sf f l/../.claude/settings.json`.",
		"The hook also denies a harmless command of this form, as in `ln -s dist public && cd public/assets && cp ../logo.png .`.",
		"A text after `echo`, `printf`, `git commit` or `git tag` does not count when the command has no pipe, no input redirection, no `$`, no backtick, and names no shell, `eval`, `source` or `.`.",
		"A command that holds the word `nocaseglob` counts in the same way, because that shell option makes a pattern match without letter case.",
		"The hook reads a relative path under the working directory that the harness sends with the call (`cwd` or `workdir`).",
		"A check that does not end in that time denies the call.")
	requireSentences(t, readRepoFile(t, "docs", "operating.md"),
		"A word that holds `/proc/NAME/cwd` counts in the same way.",
		"A symbolic link that stands before `..` in a path is followed.")
	dir := t.TempDir()
	prot := filepath.Join(dir, "prot")
	args := []string{"-policy-dir", dir, "-protect-path", prot}
	shellProt := "'" + filepath.ToSlash(prot) + "'"
	for _, payload := range []string{
		`{"tool_name":"exec_command","tool_input":{"command":` + jsonMarshalString("echo x > "+shellProt+"/f") + `}}`,
		`{"tool_name":"FooBar","tool_input":{"command":` + jsonMarshalString("python3 edit.py "+shellProt+"/f") + `}}`,
		`{"tool_name":"Bash","tool_input":{"command":` + jsonMarshalString("cd "+shellProt+" && echo x > /proc/self/cwd/f") + `}}`,
	} {
		out, _ := runHookStr(t, payload, args...)
		if got := hookDecision(t, out); got != "deny" {
			t.Errorf("%s: decision %q, want deny", payload, got)
		}
	}
}
