package main

// Installer defects found by the fifth independent review of the 0.9.0 claims
// (2026-11-10).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runInstallerExpectFail(t *testing.T, home string, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(exampleDir(t), "install.sh")}, args...)...)
	cmd.Env = installerEnv(t, home)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("install.sh %v exited 0:\n%s", args, out)
	}
	if strings.Contains(string(out), "✓") || strings.Contains(string(out), "Done.") {
		t.Errorf("install.sh %v printed a success line:\n%s", args, out)
	}
	return string(out)
}

func noBackups(t *testing.T, home string) {
	t.Helper()
	_ = filepath.Walk(home, func(p string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".bak-toolguard") {
			t.Errorf("a failed install.sh run left the backup %s", p)
		}
		return nil
	})
}

// TestInstallerChecksEveryTargetBeforeItWrites: `install.sh claude codex`
// changed the Claude Code file and then stopped on the Codex file.
func TestInstallerChecksEveryTargetBeforeItWrites(t *testing.T) {
	home := t.TempDir()
	claude, _ := installerConfigFile(home, "claude")
	codex, _ := installerConfigFile(home, "codex")
	writeConfig(t, claude, "{\"model\":\"x\"}")
	writeConfig(t, codex, "{ not JSON")
	runInstallerExpectFail(t, home, "claude", "codex", "--protect", "/abs/p")
	if data, _ := os.ReadFile(claude); string(data) != "{\"model\":\"x\"}" {
		t.Errorf("install.sh changed %s before it stopped on the Codex file: %q", claude, data)
	}
	if _, err := os.Stat(filepath.Join(home, ".tool-guard", "protect-paths")); err == nil {
		t.Error("install.sh wrote the protect-paths file in a failed run")
	}
	noBackups(t, home)
}

// TestInstallerFailedRunLeavesNoBackup: a run that stopped on a bad file left
// a .bak-toolguard file, and a later run kept that file as the first version.
func TestInstallerFailedRunLeavesNoBackup(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":               "{ this is not JSON",
		"PreToolUse is a object": "{\"hooks\":{\"PreToolUse\":{\"a\":1}}}",
		"PreToolUse is a string": "{\"hooks\":{\"PreToolUse\":\"x\"}}",
	} {
		for _, target := range []string{"claude", "codex"} {
			home := t.TempDir()
			f, _ := installerConfigFile(home, target)
			writeConfig(t, f, content)
			out := runInstallerExpectFail(t, home, target)
			if !strings.Contains(out, "\"hooks.PreToolUse\" must be an array") {
				t.Errorf("%s, %s: the message does not name the accepted shape:\n%s", name, target, out)
			}
			if data, _ := os.ReadFile(f); string(data) != content {
				t.Errorf("%s, %s: install.sh changed the config file to %q", name, target, data)
			}
			noBackups(t, home)
		}
	}
}

// TestInstallerRefusesDisableAllHooks: with "disableAllHooks": true the
// installer printed its success lines for a hook Claude Code would not run.
func TestInstallerRefusesDisableAllHooks(t *testing.T) {
	home := t.TempDir()
	f, wrapper := installerConfigFile(home, "claude")
	content := "{\"disableAllHooks\":true}"
	writeConfig(t, f, content)
	out := runInstallerExpectFail(t, home, "claude")
	if !strings.Contains(out, "disableAllHooks") {
		t.Errorf("the message does not name the setting:\n%s", out)
	}
	if data, _ := os.ReadFile(f); string(data) != content {
		t.Errorf("install.sh changed the config file to %q", data)
	}
	noBackups(t, home)
	writeConfig(t, f, "{\"disableAllHooks\":false}")
	runInstaller(t, home, "claude")
	if data, _ := os.ReadFile(f); !strings.Contains(string(data), wrapper) {
		t.Errorf("with disableAllHooks false the hook was not installed:\n%s", data)
	}
}

// TestInstallerReportsAReadOnlyConfigFile: a read-only file gave a raw bash
// error and left a backup.
func TestInstallerReportsAReadOnlyConfigFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	home := t.TempDir()
	f, _ := installerConfigFile(home, "claude")
	writeConfig(t, f, "{}")
	if err := os.Chmod(f, 0o444); err != nil {
		t.Fatal(err)
	}
	out := runInstallerExpectFail(t, home, "claude")
	if !strings.Contains(out, "is not writable") {
		t.Errorf("the message does not say the file is not writable:\n%s", out)
	}
	noBackups(t, home)
}

// TestUninstallKeepsASymlink: --uninstall replaced a symbolic link with a
// regular file.
func TestUninstallKeepsASymlink(t *testing.T) {
	home := t.TempDir()
	f, wrapper := installerConfigFile(home, "claude")
	real := filepath.Join(t.TempDir(), "dotfiles-settings.json")
	if err := os.WriteFile(real, []byte("{\"model\":\"x\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, f); err != nil {
		t.Fatal(err)
	}
	runInstaller(t, home, "claude")
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), wrapper) {
		t.Fatalf("the link target does not name %s:\n%s", wrapper, data)
	}
	cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "--uninstall", "claude")
	cmd.Env = installerEnv(t, home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh --uninstall: %v\n%s", err, out)
	}
	if fi, err := os.Lstat(f); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("--uninstall replaced the symbolic link %s (%v)", f, err)
	}
	if data, _ := os.ReadFile(real); string(data) != "{\"model\":\"x\"}\n" {
		t.Errorf("--uninstall did not restore the first version of the link target: %q", data)
	}
	if _, err := os.Stat(f + ".bak-toolguard"); err == nil {
		t.Error("--uninstall left the backup file")
	}
}

// TestExampleHookDeniesReview5Forms runs the shipped wrapper on one command
// of each class the fifth independent review found allowed.
func TestExampleHookDeniesReview5Forms(t *testing.T) {
	dir := exampleDir(t)
	home := t.TempDir()
	for _, command := range []string{
		"bash -oe pipefail -c 'rm ~/.claude/settings.json'",
		"bash -c 'X=rm; $X ~/.claude/settings.json'",
		"if true; then rm ~/.claude/settings.json; fi",
		"env A=1 rm ~/.claude/settings.json",
		"rm ~/.claude/settings.{json,x}",
		"rm ~/.claude/settings.jso?",
		"cp -r evil/.claude ~/",
		"cp -rT x ~/.claude",
		"sed -Ei s/a/b/ ~/.claude/settings.json",
		"echo 'rm ~/.claude/settings.json' | bash",
		"cd ~/.claude && rm settings.json",
	} {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "deny" {
				t.Errorf("%s, %s: decision = %q, want deny", harness, command, got)
			}
		}
	}
	for _, command := range []string{"if true; then echo hi; fi", "cd ~/project && rm settings.json", "cp a.{txt,md} ~/docs/", "echo hi | bash", "sed -n p notes.txt"} {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "allow" {
				t.Errorf("%s, %s: decision = %q, want allow", harness, command, got)
			}
		}
	}
}

// The tests below cover the installer defects found by the sixth independent
// review (2026-11-10).

// TestUninstallWithoutBackupKeepsTheFile: a second --uninstall, or one after
// a failed install, deleted the user's settings file.
func TestUninstallWithoutBackupKeepsTheFile(t *testing.T) {
	uninstall := func(home string, target string) string {
		cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "--uninstall", target)
		cmd.Env = installerEnv(t, home)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install.sh --uninstall %s: %v\n%s", target, err, out)
		}
		return string(out)
	}
	for _, target := range []string{"claude", "codex", "antigravity"} {
		home := t.TempDir()
		f, wrapper := installerConfigFile(home, target)
		if target == "antigravity" {
			f, wrapper = filepath.Join(home, ".gemini", "config", "hooks.json"), "antigravity-cli-hook.sh"
		}
		writeConfig(t, f, "{\"model\":\"x\"}")
		runInstaller(t, home, target)
		uninstall(home, target)
		// A second run has no backup to restore.
		uninstall(home, target)
		if data, err := os.ReadFile(f); err != nil || string(data) != "{\"model\":\"x\"}" {
			t.Errorf("%s: a second --uninstall changed the file: %q (%v)", target, data, err)
		}
		// With the backup gone, --uninstall removes its entry and keeps the rest.
		runInstaller(t, home, target)
		if err := os.Remove(f + ".bak-toolguard"); err != nil {
			t.Fatal(err)
		}
		out := uninstall(home, target)
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: --uninstall without a backup deleted the file: %v", target, err)
		}
		if strings.Contains(string(data), wrapper) {
			t.Errorf("%s: --uninstall without a backup left its entry:\n%s", target, data)
		}
		if !strings.Contains(string(data), "\"model\"") {
			t.Errorf("%s: --uninstall without a backup dropped the user's key:\n%s", target, data)
		}
		if !strings.Contains(out, "Removed the Tool Guard entry and kept the rest of the file.") {
			t.Errorf("%s: --uninstall does not say what it did:\n%s", target, out)
		}
	}
}

// TestInstallerChecksTheDirectoryBeforeItWrites: with ~/.codex a file, or a
// directory the user cannot write to, `install.sh claude codex` changed the
// Claude Code file, left a backup, and then stopped.
func TestInstallerChecksTheDirectoryBeforeItWrites(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only directory")
	}
	for name, block := range map[string]func(dir string){
		"a file": func(dir string) {
			if err := os.WriteFile(dir, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a read-only directory": func(dir string) {
			if err := os.Mkdir(dir, 0o555); err != nil {
				t.Fatal(err)
			}
		},
	} {
		home := t.TempDir()
		claude, _ := installerConfigFile(home, "claude")
		codex, _ := installerConfigFile(home, "codex")
		writeConfig(t, claude, "{\"model\":\"x\"}")
		block(filepath.Dir(codex))
		out := runInstallerExpectFail(t, home, "claude", "codex", "--protect", "/abs/p")
		if !strings.Contains(out, "No config file was changed and no hook was installed.") {
			t.Errorf("%s: the message does not say that nothing changed:\n%s", name, out)
		}
		if data, _ := os.ReadFile(claude); string(data) != "{\"model\":\"x\"}" {
			t.Errorf("%s: install.sh changed %s: %q", name, claude, data)
		}
		if _, err := os.Stat(filepath.Join(home, ".tool-guard", "protect-paths")); err == nil {
			t.Errorf("%s: install.sh wrote the protect-paths file in a failed run", name)
		}
		noBackups(t, home)
	}
}

// TestUninstallWithoutBackupKeepsOtherHooks: the edit removes the entry of
// the installer and no other hook.
func TestUninstallWithoutBackupKeepsOtherHooks(t *testing.T) {
	home := t.TempDir()
	f, wrapper := installerConfigFile(home, "claude")
	writeConfig(t, f, "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"/opt/my-hook\"}]}]}}")
	runInstaller(t, home, "claude")
	if err := os.Remove(f + ".bak-toolguard"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "--uninstall", "claude")
	cmd.Env = installerEnv(t, home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh --uninstall claude: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "/opt/my-hook") {
		t.Errorf("--uninstall without a backup removed the user's own hook:\n%s", data)
	}
	if strings.Contains(string(data), wrapper) {
		t.Errorf("--uninstall without a backup left its entry:\n%s", data)
	}
}

// TestUninstallReportsAConfigFileItCannotWrite: with a backup and a config
// file that cannot be written, --uninstall printed the raw shell error. It
// now names the file, keeps the backup, restores the other agent and ends
// with exit code 1.
func TestUninstallReportsAConfigFileItCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	home := t.TempDir()
	claude, _ := installerConfigFile(home, "claude")
	codex, _ := installerConfigFile(home, "codex")
	writeConfig(t, claude, "{\"model\":\"x\"}")
	writeConfig(t, codex, "{\"model\":\"y\"}")
	runInstaller(t, home, "claude", "codex")
	if err := os.Chmod(claude, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(claude, 0o644) })
	out := runInstallerExpectFail(t, home, "--uninstall", "claude", "codex")
	want := "✗ " + claude + " could not be written, so it was not restored. The copy is still at " + claude + ".bak-toolguard."
	if !strings.Contains(out, want) {
		t.Errorf("the output does not hold %q:\n%s", want, out)
	}
	if strings.Contains(out, "Permission denied") || strings.Contains(out, "install.sh: line") {
		t.Errorf("the output holds a raw shell error:\n%s", out)
	}
	if _, err := os.Stat(claude + ".bak-toolguard"); err != nil {
		t.Errorf("the backup of the file that was not restored is gone: %v", err)
	}
	if data, _ := os.ReadFile(codex); string(data) != "{\"model\":\"y\"}" {
		t.Errorf("the other agent was not restored: %q", data)
	}
	requireSentences(t, readRepoFile(t, "examples", "coding-agent-guard", "README.md"),
		"When `--uninstall` cannot write a config file, it says so, keeps the copy, goes on with the other agents and ends with exit code 1.")
}

// TestUninstallGoesOnWhenACopyCannotBeRemoved: the config file can be
// written and its directory cannot, so the copy stays. --uninstall stopped
// there with the raw shell error and did not restore the other agent.
func TestUninstallGoesOnWhenACopyCannotBeRemoved(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can remove a file from a read-only directory")
	}
	home := t.TempDir()
	claude, _ := installerConfigFile(home, "claude")
	codex, _ := installerConfigFile(home, "codex")
	writeConfig(t, claude, "{\"model\":\"x\"}")
	writeConfig(t, codex, "{\"model\":\"y\"}")
	runInstaller(t, home, "claude", "codex")
	dir := filepath.Dir(claude)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	out := runInstallerExpectFail(t, home, "--uninstall", "claude", "codex")
	want := "✗ " + claude + ".bak-toolguard could not be removed. " + claude + " was restored."
	if !strings.Contains(out, want) {
		t.Errorf("the output does not hold %q:\n%s", want, out)
	}
	if strings.Contains(out, "Permission denied") || strings.Contains(out, "install.sh: line") {
		t.Errorf("the output holds a raw shell error:\n%s", out)
	}
	if data, _ := os.ReadFile(claude); string(data) != "{\"model\":\"x\"}" {
		t.Errorf("the config file was not restored: %q", data)
	}
	if data, _ := os.ReadFile(codex); string(data) != "{\"model\":\"y\"}" {
		t.Errorf("the other agent was not restored: %q", data)
	}
	requireSentences(t, readRepoFile(t, "examples", "coding-agent-guard", "README.md"),
		"When it restored a config file and cannot remove the copy, it says so, goes on and ends with exit code 1.")
}

// TestUninstallWithoutACopyFailsOnAFileItCannotEdit: no backup exists and
// the config file is read-only. --uninstall printed that the file was not
// changed and ended with exit code 0, with the Tool Guard entry still there.
func TestUninstallWithoutACopyFailsOnAFileItCannotEdit(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	home := t.TempDir()
	claude, _ := installerConfigFile(home, "claude")
	codex, _ := installerConfigFile(home, "codex")
	writeConfig(t, claude, "{\"model\":\"x\"}")
	writeConfig(t, codex, "{\"model\":\"y\"}")
	runInstaller(t, home, "claude", "codex")
	if err := os.Remove(claude + ".bak-toolguard"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(claude)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(claude, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(claude, 0o644) })
	out := runInstallerExpectFail(t, home, "--uninstall", "claude", "codex")
	want := "✗ no backup of " + claude + " exists and the file could not be edited. The file was not changed."
	if !strings.Contains(out, want) {
		t.Errorf("the output does not hold %q:\n%s", want, out)
	}
	if after, _ := os.ReadFile(claude); string(after) != string(before) {
		t.Errorf("the file changed:\n%s", after)
	}
	if data, _ := os.ReadFile(codex); string(data) != "{\"model\":\"y\"}" {
		t.Errorf("the other agent was not restored: %q", data)
	}
	requireSentences(t, readRepoFile(t, "examples", "coding-agent-guard", "README.md"),
		"Without a copy, a config file that `--uninstall` cannot edit stays as it was, and the run ends with exit code 1.")
}

// TestInstallerChecksTheProtectedPathsFileBeforeItWrites: with --protect, a
// protected-paths file the installer cannot write stops the run before any
// config file is changed.
func TestInstallerChecksTheProtectedPathsFileBeforeItWrites(t *testing.T) {
	home := t.TempDir()
	claude, _ := installerConfigFile(home, "claude")
	writeConfig(t, claude, "{\"model\":\"x\"}")
	if err := os.MkdirAll(filepath.Join(home, ".tool-guard", "protect-paths"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := runInstallerExpectFail(t, home, "claude", "--protect", "/abs/p")
	if !strings.Contains(out, "No config file was changed and no hook was installed.") {
		t.Errorf("the message does not say that nothing changed:\n%s", out)
	}
	if data, _ := os.ReadFile(claude); string(data) != "{\"model\":\"x\"}" {
		t.Errorf("install.sh changed %s: %q", claude, data)
	}
	noBackups(t, home)
}

// TestInstallerReportsALinkToNothingAndADirectory: a symbolic link to a file
// that does not exist, and a directory in place of the config file, gave a
// raw shell error.
func TestInstallerReportsALinkToNothingAndADirectory(t *testing.T) {
	home := t.TempDir()
	f, _ := installerConfigFile(home, "claude")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nowhere", "real.json"), f); err != nil {
		t.Fatal(err)
	}
	out := runInstallerExpectFail(t, home, "claude")
	if !strings.Contains(out, "is a symbolic link to a file that does not exist.") || !strings.Contains(out, "No config file was changed") {
		t.Errorf("link to nothing:\n%s", out)
	}
	noBackups(t, home)

	home = t.TempDir()
	f, _ = installerConfigFile(home, "claude")
	if err := os.MkdirAll(f, 0o755); err != nil {
		t.Fatal(err)
	}
	out = runInstallerExpectFail(t, home, "claude")
	if !strings.Contains(out, "is not a regular file.") || !strings.Contains(out, "No config file was changed") {
		t.Errorf("directory in place of the file:\n%s", out)
	}
}

// TestExampleHookDeniesReview6Forms runs the shipped wrapper on one command
// of each class the sixth independent review found allowed, and on the
// command examples of the Protected paths section of the example README.
func TestExampleHookDeniesReview6Forms(t *testing.T) {
	dir := exampleDir(t)
	home := t.TempDir()
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	deny := []string{
		"python3 edit.py ~/.claude/settings.json",
		"git checkout ~/.claude/settings.json",
		"cd ~/.claude && python3 edit.py settings.json",
		"env -S 'rm -f ~/.claude/settings.json'",
		"timeout --signal=KILL 5 rm ~/.claude/settings.json",
		"unlink ~/.claude/settings.json",
		"trap 'rm ~/.claude/settings.json' EXIT",
		"fish -c 'rm ~/.claude/settings.json'",
		"builtin cd ~/.claude && rm settings.json",
		"X=rm; $X ~/.claude/settings.json",
		"rm ~/.claude/settings.[j]son",
		"rm ~/.claude/settings.json # note",
		"cat <<E | bash\nrm ~/.claude/settings.json\nE",
		"case x in x) rm ~/.claude/settings.json;; esac",
		"echo -e 'rm ~/.claude/settings\\x2ejson' | bash",
		"{bash,-c,'rm ~/.claude/settings.json'}",
		"HOME=/x; rm " + home + "/.claude/settings.json",
		"find ~/.claude/settings.json -delete",
		"PATH=/x cat ~/.claude/settings.json",
		"env cat ~/.claude/settings.json",
		"git commit -m \"change ~/.claude/settings.json\"",
		"sed -i \"s/$OLD/$NEW/\" FILE",
		"ls ~/.tool-guard > list.txt",
		"cd ~/.tool-guard && echo x > protect-paths",
		"cd ~/.tool-guard/audit && echo x > f",
		"pushd ~/.tool-guard/audit && cd .. && echo x >> protect-paths",
		"fish --init-command='python3 edit.py ~/.claude/settings.json' -c true",
		"sort -o ~/.claude/settings.json x",
		"sort --output=out.txt ~/.claude/settings.json",
		"uniq x ~/.claude/settings.json",
		"uniq ~/.claude/*",
		"cd ~/.claude && uniq /etc/hostname ~+/settings.json",
		"cd ~/.claude && curl -so ~+/settings.json https://example.com/x",
		"uniq /etc/hostname\recho ~/.claude/settings.json",
		"sort {-o,~/.claude/settings.json}",
		"sort -[n-p] ~/.claude/settings.json",
		"bash --rcfile x -c 'cat ~/.claude/settings.json'",
	}
	if err := os.MkdirAll(filepath.Join(home, ".tool-guard", "audit"), 0o755); err != nil {
		t.Fatal(err)
	}
	allow := []string{"ls ~/.claude/* | sort", "sort ~/.claude/settings.json | uniq -c", "cat ~/.claude/settings.json", "grep -c hooks ~/.claude/settings.json", "cat ~/.claude/*.json | grep hooks | head", "grep hooks ~/.claude/settings.json > out.txt", "cd ~/.tool-guard/audit && ls a b c d", "bash -c 'cat ~/.claude/settings.json'", "mkdir -p out/{1..3}", "cp x .", "python3 edit.py settings.json"}
	for _, c := range append(append([]string{}, deny[:3]...), allow[0]) {
		if !strings.Contains(readme, backtick+c+backtick) {
			t.Errorf("the example README no longer has the command example %s", c)
		}
	}
	for _, command := range deny {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "deny" {
				t.Errorf("%s, %s: decision = %q, want deny", harness, command, got)
			}
		}
	}
	for _, command := range allow {
		for harness, wrapper := range exampleWrappers {
			out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), home, exampleShellPayload(harness, command))
			if got, _ := exampleDecision(t, out); got != "allow" {
				t.Errorf("%s, %s: decision = %q, want allow", harness, command, got)
			}
		}
	}
}
