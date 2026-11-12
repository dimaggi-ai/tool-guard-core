package main

// Installer defects found by the third independent review of the 0.9.0 claims
// (2026-11-10).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func installerConfigFile(home, target string) (file, wrapper string) {
	if target == "codex" {
		return filepath.Join(home, ".codex", "hooks.json"), "codex-hook.sh"
	}
	return filepath.Join(home, ".claude", "settings.json"), "claude-code-hook.sh"
}

func writeConfig(t *testing.T, f, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInstallerFailsWhenJqCannotEdit: before the fix, install.sh printed its
// success lines and exited 0 when jq failed, and the config file held no hook.
func TestInstallerFailsWhenJqCannotEdit(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	for name, content := range map[string]string{
		"not JSON":           "{ this is not JSON",
		"hooks is a string":  "{\"hooks\":\"str\"}",
		"hooks is an array":  "{\"hooks\":[]}",
		"entry is no object": "{\"hooks\":{\"PreToolUse\":[\"x\"]}}",
		"only whitespace":    " \n\t\n",
		"two JSON values":    "{} {}",
		"a JSON array":       "[]",
	} {
		for _, target := range []string{"claude", "codex"} {
			home := t.TempDir()
			f, _ := installerConfigFile(home, target)
			writeConfig(t, f, content)
			cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), target)
			cmd.Env = installerEnv(t, home)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Errorf("%s, %s: install.sh exited 0:\n%s", name, target, out)
			}
			if strings.Contains(string(out), "✓") || strings.Contains(string(out), "Done.") {
				t.Errorf("%s, %s: install.sh printed a success line after jq failed:\n%s", name, target, out)
			}
			if data, _ := os.ReadFile(f); string(data) != content {
				t.Errorf("%s, %s: install.sh changed the config file to %q", name, target, data)
			}
		}
	}
}

// TestInstallerKeepsAnEntryWithoutHooks: an entry without a "hooks" array made
// jq fail before. It must stay, and the hook must be added once.
func TestInstallerKeepsAnEntryWithoutHooks(t *testing.T) {
	for _, target := range []string{"claude", "codex"} {
		home := t.TempDir()
		f, wrapper := installerConfigFile(home, target)
		writeConfig(t, f, "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Keep\"}]}}")
		runInstaller(t, home, target)
		runInstaller(t, home, target)
		data, _ := os.ReadFile(f)
		if !strings.Contains(string(data), "\"Keep\"") {
			t.Errorf("%s: install.sh dropped an entry without hooks:\n%s", target, data)
		}
		if n := strings.Count(string(data), wrapper); n != 1 {
			t.Errorf("%s: after two installs the config names %s %d times, want 1:\n%s", target, wrapper, n, data)
		}
	}
}

// TestInstallerUsesConfigDirVariables: Claude Code reads CLAUDE_CONFIG_DIR and
// Codex reads CODEX_HOME. The installer must write where the harness reads,
// and --uninstall must restore the same files.
func TestInstallerUsesConfigDirVariables(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	home := t.TempDir()
	cdir := filepath.Join(t.TempDir(), "claude-config")
	xdir := filepath.Join(t.TempDir(), "codex-home")
	run := func(args ...string) {
		cmd := exec.Command("bash", append([]string{filepath.Join(exampleDir(t), "install.sh")}, args...)...)
		cmd.Env = append(installerEnv(t, home), "CLAUDE_CONFIG_DIR="+cdir, "CODEX_HOME="+xdir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("install.sh %v: %v\n%s", args, err, out)
		}
	}
	run("claude", "codex")
	for f, wrapper := range map[string]string{
		filepath.Join(cdir, "settings.json"): "claude-code-hook.sh",
		filepath.Join(xdir, "hooks.json"):    "codex-hook.sh",
	} {
		data, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(data), wrapper) {
			t.Errorf("%s does not name %s (%v):\n%s", f, wrapper, err, data)
		}
	}
	for _, f := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".codex", "hooks.json")} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("install.sh wrote %s although the config directory variable was set", f)
		}
	}
	run("--uninstall", "claude", "codex")
	for _, f := range []string{filepath.Join(cdir, "settings.json"), filepath.Join(xdir, "hooks.json")} {
		if data, _ := os.ReadFile(f); strings.Contains(string(data), "-hook.sh") {
			t.Errorf("after --uninstall %s still names a hook:\n%s", f, data)
		}
	}
}

// TestExampleHookDeniesTildeWriteToHarnessConfig runs the shipped wrapper: a
// shell write to a protected config file written with a tilde must be denied.
func TestExampleHookDeniesTildeWriteToHarnessConfig(t *testing.T) {
	dir := exampleDir(t)
	home := t.TempDir()
	for _, command := range []string{
		"echo x > ~/.claude/settings.json",
		"cp /tmp/a ~/.codex/hooks.json",
		"echo /tmp > ~/.tool-guard/protect-paths",
		"bash -c 'echo x > ~/.gemini/config/hooks.json'",
	} {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "deny" {
				t.Errorf("%s, %s: decision = %q, want deny", harness, command, got)
			}
		}
	}
	for harness, wrapper := range exampleWrappers {
		out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, "echo x > ~/notes.txt"))
		if got, _ := exampleDecision(t, out); got != "allow" {
			t.Errorf("%s: a tilde write outside the protected paths: decision = %q, want allow", harness, got)
		}
	}
}

// TestInstallerHandlesAnEmptyConfigFile: before the fix, jq printed nothing
// for a 0-byte file, the installer moved the empty output over it and printed
// its success lines. An empty file now gets the hook.
func TestInstallerHandlesAnEmptyConfigFile(t *testing.T) {
	requireSentences(t, readRepoFile(t, "examples", "coding-agent-guard", "README.md"),
		"A config file of 0 bytes is treated as \x60{}\x60.",
		"The installer checks every config file you named before it changes the first one.",
		"It also checks that it can write to the directory of each file.",
		"When no copy exists, "+backtick+"--uninstall"+backtick+" removes the installer's own entry and keeps the rest of the file.",
		"A run that stops on one of them changes no config file and leaves no backup.",
		"or the result is not one JSON object, the installer stops with exit code 1 and leaves the file as it was.",
		"\x60install.sh codex\x60 also stops with exit code 1, before it changes the file, when \x60hooks.json\x60 has a top-level \x60PreToolUse\x60 key with an entry that is not from this installer.")
	for _, target := range []string{"claude", "codex", "antigravity"} {
		home := t.TempDir()
		f, wrapper := installerConfigFile(home, target)
		if target == "antigravity" {
			f, wrapper = filepath.Join(home, ".gemini", "config", "hooks.json"), "antigravity-cli-hook.sh"
		}
		writeConfig(t, f, "")
		runInstaller(t, home, target)
		data, _ := os.ReadFile(f)
		if !strings.Contains(string(data), wrapper) {
			t.Errorf("%s: after install.sh the config file does not name %s:\n%q", target, wrapper, data)
		}
	}
}

// TestInstallerKeepsAnEntryWithNullHooks: "hooks": null made jq fail with a
// message that did not describe the file.
func TestInstallerKeepsAnEntryWithNullHooks(t *testing.T) {
	for _, target := range []string{"claude", "codex"} {
		home := t.TempDir()
		f, wrapper := installerConfigFile(home, target)
		writeConfig(t, f, "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Keep\",\"hooks\":null}]}}")
		runInstaller(t, home, target)
		data, _ := os.ReadFile(f)
		if !strings.Contains(string(data), "\"Keep\"") || strings.Count(string(data), wrapper) != 1 {
			t.Errorf("%s: want the entry kept and the hook added once:\n%s", target, data)
		}
	}
}

// TestInstallerKeepsModeAndSymlink: the installer replaced the config file
// with a mode-600 temp file, and replaced a symbolic link with a regular file.
func TestInstallerKeepsModeAndSymlink(t *testing.T) {
	home := t.TempDir()
	f, wrapper := installerConfigFile(home, "claude")
	real := filepath.Join(t.TempDir(), "dotfiles-settings.json")
	if err := os.WriteFile(real, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, f); err != nil {
		t.Fatal(err)
	}
	runInstaller(t, home, "claude")
	if fi, err := os.Lstat(f); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("install.sh replaced the symbolic link %s (%v)", f, err)
	}
	fi, err := os.Stat(real)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the link target has mode %v, want 0644 (%v)", fi.Mode().Perm(), err)
	}
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), wrapper) {
		t.Errorf("the link target does not name %s:\n%s", wrapper, data)
	}
}

// TestExampleHookDeniesDirectoryAndOptionForms runs the shipped wrapper on the
// forms the fourth independent review found allowed (2026-11-10).
func TestExampleHookDeniesDirectoryAndOptionForms(t *testing.T) {
	dir := exampleDir(t)
	home := t.TempDir()
	for _, command := range []string{
		"bash -ce 'echo x > ~/.claude/settings.json'",
		"bash -c -- 'echo x > ~/.claude/settings.json'",
		"bash -c \"rm '$HOME/.claude/settings.json'\"",
		"bash -c $'rm ~/.claude/settings.json'",
		"cp settings.json ~/.claude/",
		"cp -t ~/.codex hooks.json",
		"mv ~/.claude ~/.claude-old",
		"chmod 000 ~/.tool-guard",
	} {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "deny" {
				t.Errorf("%s, %s: decision = %q, want deny", harness, command, got)
			}
		}
	}
	for _, command := range []string{"cp notes.txt ~/", "bash -c 'echo hi'", "mkdir -p ~/.claude"} {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "allow" {
				t.Errorf("%s, %s: decision = %q, want allow", harness, command, got)
			}
		}
	}
}
