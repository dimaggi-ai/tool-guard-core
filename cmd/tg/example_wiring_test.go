package main

// The shipped coding-agent example must enforce the same decision path that
// examples/coding-agent-guard/verify-harnesses.sh measures.
//
// This test exists because of a measured review finding (2026-11-09): the
// example's config files wired reference adapters that ran `tg evaluate` against
// a single shell-scoped policy, while the verification script generated its own
// hook calling `tg hook -policy-dir policies -protect-path ...`. Every
// end-to-end PASS therefore described a configuration no operator had installed,
// and the installed adapters allowed all seven protected payloads from the
// verification run. A docs-only fix would let that recur; this test does not.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exampleDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "examples", "coding-agent-guard"))
	if err != nil {
		t.Fatalf("resolve example dir: %v", err)
	}
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("example dir missing: %v", err)
	}
	return d
}

// hookCommandsFromConfig returns every hook command string a harness would run,
// from any config file in config/. It understands both the Claude/Codex shape
// ({"hooks":{"PreToolUse":[...]}}, or a top-level PreToolUse array) and the
// Antigravity named-hook map.
func hookCommandsFromConfig(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	var out []string

	var entries []struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	collect := func(b []byte) {
		if len(b) == 0 {
			return
		}
		// Both shapes occur: an object with a PreToolUse key, and (Antigravity)
		// an outer named-hook map whose values are objects with PreToolUse.
		var asObj map[string]json.RawMessage
		if json.Unmarshal(b, &asObj) == nil {
			if inner, ok := asObj["PreToolUse"]; ok {
				_ = json.Unmarshal(inner, &entries)
				for _, e := range entries {
					for _, h := range e.Hooks {
						if h.Command != "" {
							out = append(out, h.Command)
						}
					}
				}
			}
			for _, v := range asObj {
				var arr []json.RawMessage
				if json.Unmarshal(v, &arr) == nil && len(arr) > 0 {
					// a bare PreToolUse array
					_ = json.Unmarshal(v, &entries)
					for _, e := range entries {
						for _, h := range e.Hooks {
							if h.Command != "" {
								out = append(out, h.Command)
							}
						}
					}
				}
			}
			return
		}
		var asArr []json.RawMessage
		if json.Unmarshal(b, &asArr) == nil {
			_ = json.Unmarshal(b, &entries)
			for _, e := range entries {
				for _, h := range e.Hooks {
					if h.Command != "" {
						out = append(out, h.Command)
					}
				}
			}
		}
	}
	collect(doc["hooks"])
	collect(doc["PreToolUse"])
	// Antigravity: any top-level key that is not a known scalar holds a hook map.
	for k, v := range doc {
		if k == "hooks" || k == "PreToolUse" || k == "_comment" {
			continue
		}
		collect(v)
	}
	return out
}

// TestShippedExampleConfigsWireTheVerifiedPath checks the static half: every
// command the shipped configs tell a harness to run must be a script in this
// example, and that script must drive `tg hook` (the decision path the engine
// tests and the conformance corpus cover), not a hand-rolled evaluator.
func TestShippedExampleConfigsWireTheVerifiedPath(t *testing.T) {
	dir := exampleDir(t)
	cfgs, err := filepath.Glob(filepath.Join(dir, "config", "*.json"))
	if err != nil || len(cfgs) == 0 {
		t.Fatalf("no config files found in %s/config", dir)
	}
	for _, cfg := range cfgs {
		cmds := hookCommandsFromConfig(t, cfg)
		if len(cmds) == 0 {
			t.Fatalf("%s declares no hook command; the example would install nothing", cfg)
		}
		for _, c := range cmds {
			script := strings.Fields(c)[0]
			script = strings.Replace(script, "__HOOK_DIR__", filepath.Join(dir, "hooks"), 1)
			if !filepath.IsAbs(script) {
				t.Fatalf("%s: hook command %q is not an absolute path template", cfg, c)
			}
			body, err := os.ReadFile(script)
			if err != nil {
				t.Fatalf("%s: wired script %s is missing: %v", cfg, script, err)
			}
			// Comments may name the old approach to warn about it; only the code
			// that runs counts.
			text := codeOnly(string(body))
			if strings.Contains(text, "tg evaluate") {
				t.Errorf("%s wires %s, which evaluates a single policy with `tg evaluate`. The verified decision path is `tg hook -policy-dir`: only tg hook maps harness tool names, parameter aliases and output dialects, and only the policies in policies/ carry the leak guards. Rewrite the script to call tg hook.", cfg, script)
			}
			if !strings.Contains(text, "guard-hook.sh") {
				t.Errorf("%s wires %s, which does not hand off to hooks/guard-hook.sh", cfg, script)
			}
			guard, err := os.ReadFile(filepath.Join(dir, "hooks", "guard-hook.sh"))
			if err != nil {
				t.Fatalf("read hooks/guard-hook.sh: %v", err)
			}
			guardCode := codeOnly(string(guard))
			for _, need := range []string{"args=(hook)", `out="$("$TG_BIN" "${args[@]}")"`} {
				if !strings.Contains(guardCode, need) {
					t.Errorf("hooks/guard-hook.sh no longer contains %q, so it does not run `tg hook`", need)
				}
			}
			info, err := os.Stat(script)
			if err == nil && info.Mode()&0o111 == 0 {
				t.Errorf("%s: %s is not executable; the harness would fail to run it and fail open", cfg, script)
			}
		}
	}
}

// codeOnly drops comment lines so a script can explain what it replaced without
// tripping the check that it must not call the thing it replaced.
func codeOnly(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// installExample runs install.sh for the three harnesses with home as the home
// directory, one --protect argument per path, and returns the wrapper script
// each harness config names.
func installExample(t *testing.T, home string, protect ...string) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	dir := exampleDir(t)
	args := []string{filepath.Join(dir, "install.sh"), "claude", "codex", "antigravity"}
	for _, p := range protect {
		args = append(args, "--protect", p)
	}
	cmd := exec.Command("bash", args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TG_BIN=" + exampleHooksTg(t)}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	configs := map[string]string{
		"claude":      filepath.Join(home, ".claude", "settings.json"),
		"codex":       filepath.Join(home, ".codex", "hooks.json"),
		"antigravity": filepath.Join(home, ".gemini", "config", "hooks.json"),
	}
	scripts := map[string]string{}
	for harness, cfg := range configs {
		cmds := exampleUnique(hookCommandsFromConfig(t, cfg))
		if len(cmds) != 1 {
			t.Fatalf("%s: hook commands = %q, want exactly one", cfg, cmds)
		}
		if strings.ContainsAny(cmds[0], " \t'\"\\$`") {
			t.Fatalf("%s: hook command %q is not one bare path", cfg, cmds[0])
		}
		scripts[harness] = cmds[0]
	}
	return scripts
}

// TestInstallerProtectPathsAreHonoured: a path given with --protect must be
// protected by the command each harness config names. It covers a plain path,
// a path with a space and a path with a comma, for a write-tool call and for a
// shell redirect, and it requires that a path outside the list stays writable.
func TestInstallerProtectPathsAreHonoured(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "work")
	plain := filepath.Join(work, "plain")
	spaced := filepath.Join(work, "my docs")
	comma := filepath.Join(work, "a,b")
	scripts := installExample(t, home, plain, spaced, comma)
	targets := map[string]string{
		filepath.Join(plain, "x.txt"):         "deny",
		filepath.Join(spaced, "x.txt"):        "deny",
		filepath.Join(comma, "x.txt"):         "deny",
		filepath.Join(work, "other", "x.txt"): "allow",
	}
	for harness, script := range scripts {
		for target, want := range targets {
			out := runExampleHook(t, script, home, exampleWritePayload(harness, target, "x"))
			if got, _ := exampleDecision(t, out); got != want {
				t.Errorf("%s: write tool at %s: decision = %q, want %q", harness, target, got, want)
			}
			out = runExampleHook(t, script, home, exampleShellPayload(harness, "echo hi > '"+target+"'"))
			if got, _ := exampleDecision(t, out); got != want {
				t.Errorf("%s: shell redirect at %s: decision = %q, want %q", harness, target, got, want)
			}
		}
	}
}

// TestInstallerGeneratedCommandIsInert: a --protect path is data. A path whose
// name holds a command substitution must run nothing when install.sh records
// it and nothing when the hook reads it, and the path must be protected under
// its literal name.
func TestInstallerGeneratedCommandIsInert(t *testing.T) {
	home := t.TempDir()
	marker := filepath.Join(home, "marker")
	dollar := filepath.Join(home, "work", "$(touch "+marker+").txt")
	backtick := filepath.Join(home, "work", "`touch "+marker+"`.txt")
	scripts := installExample(t, home, dollar, backtick)
	for harness, script := range scripts {
		for _, target := range []string{dollar, backtick} {
			out := runExampleHook(t, script, home, exampleWritePayload(harness, target, "x"))
			if got, _ := exampleDecision(t, out); got != "deny" {
				t.Errorf("%s: write tool at %s: decision = %q, want deny", harness, target, got)
			}
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("a --protect path was executed: %s exists", marker)
	}
}

// installerPrintedLines is every line of install.sh that contains echo, printf
// or a here-document mark, in file order, without the leading and trailing
// white space. Comment lines are left out. A printed line is a statement to
// the operator. TestInstallerPrintedLinesArePinned fails when install.sh
// prints a line that is not in this list. Before you add a line here, check
// its statement against docs/support-matrix.md.
var installerPrintedLines = []string{
	"command -v jq >/dev/null 2>&1 || { echo \"install.sh needs 'jq' on PATH\"; exit 2; }",
	"[ \"$i\" -lt \"${#ARGS[@]}\" ] || { echo \"--protect needs a path\"; exit 2; }",
	"*) echo \"unknown arg: $a (want: claude codex antigravity --protect PATH --uninstall)\"; exit 2 ;;",
	"[ \"${#TARGETS[@]}\" -eq 0 ] && { echo \"no supported agent (claude/codex/agy) found on PATH\"; exit 1; }",
	"echo \"install.sh cannot install from a path containing whitespace, a quote, a backslash or a dollar sign:\"",
	"echo \"  $HOOK_DIR\"",
	"echo \"Move the repository to a path without those characters and run install.sh again.\"",
	"*) echo \"--protect needs an absolute path, got: $pth\"; exit 2 ;;",
	"*$'\\n'*) echo \"--protect rejects a path containing a newline\"; exit 2 ;;",
	"grep -Fxq -- \"$pth\" \"$PROTECT_FILE\" || printf '%s\\n' \"$pth\" >> \"$PROTECT_FILE\"",
	"echo \"✓ protected paths recorded in $PROTECT_FILE\"",
	"echo \"→ building tg ...\"",
	"cp -p \"$1\" \"$1.bak-toolguard\" && echo \"  backed up $1 -> $1.bak-toolguard\"",
	"[ -f \"$f\" ] || echo '{}' > \"$f\"",
	"echo \"✓ Claude Code: PreToolUse(all tools) -> $hook\"",
	"echo \"  $f\"",
	"[ -f \"$f\" ] || echo '{}' > \"$f\"",
	"echo \"✓ Codex: PreToolUse(all tools) -> $hook\"",
	"echo \"  $f\"",
	"echo \"  Codex will not run this hook until you make it trust it: start codex,\"",
	"echo \"  review and accept the hook when prompted. An untrusted hooks.json gives\"",
	"echo \"  no protection and no error (measured on 0.166.0).\"",
	"[ -f \"$f\" ] || echo '{}' > \"$f\"",
	"echo \"✓ Antigravity: PreToolUse(all tools) -> $hook\"",
	"echo \"  $f\"",
	"mv \"$f.bak-toolguard\" \"$f\"; echo \"↩ restored $f\"",
	"rm -f \"$f\"; echo \"↩ removed $f (no backup existed)\"",
	"echo",
	"echo \"Done. Each harness now calls its wrapper in $HOOK_DIR\"",
	"echo \"The wrappers run 'tg hook' with the five policies in $HERE/policies\"",
	"echo",
	"echo \"Check it against the harness you run:\"",
	"echo \"  ./examples/coding-agent-guard/verify-harnesses.sh   (needs the CLIs, makes paid model calls)\"",
	"echo \"  ./examples/coding-agent-guard/run.sh                (offline: prints the decision each wrapper returns)\"",
	"echo",
	"echo \"What a harness does with a decision differs by harness and by version.\"",
	"echo \"docs/support-matrix.md lists what was measured and on which version.\"",
	"echo \"The Codex wrapper returns an escalation as a denial. The other two wrappers\"",
	"echo \"return it as a request for approval. To change that for one harness, set\"",
	"echo \"TG_ESCALATE_AS=deny or TG_ESCALATE_AS=ask in the environment the harness runs in.\"",
}

func TestInstallerPrintedLinesArePinned(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(exampleDir(t), "install.sh"))
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	var got []string
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "#") {
			continue
		}
		if strings.Contains(s, "echo") || strings.Contains(s, "printf") || strings.Contains(s, "<<") {
			got = append(got, s)
		}
	}
	for i := 0; i < len(got) || i < len(installerPrintedLines); i++ {
		have, want := "(no line)", "(no line)"
		if i < len(got) {
			have = got[i]
		}
		if i < len(installerPrintedLines) {
			want = installerPrintedLines[i]
		}
		if have != want {
			t.Fatalf("printing line %d of install.sh is not the pinned one.\n have: %s\n want: %s\nA new printed line is a new statement to the operator: check it against docs/support-matrix.md, then update installerPrintedLines", i+1, have, want)
		}
	}
}
