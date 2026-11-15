package main

// Tests added after the third independent review of the 0.9.0 claims
// (2026-11-10). Each one closes a mutation that the suite accepted before, or
// pins an installer fix.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func runInstaller(t *testing.T, home string, args ...string) string {
	t.Helper()
	exampleHooksTg(t)
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(exampleDir(t), "install.sh")}, args...)...)
	cmd.Env = installerEnv(t, home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// oldCodexHooksFile is what install.sh 0.8.1 wrote: its entry under a
// top-level PreToolUse key. Codex CLI 0.166.0 rejects a hooks.json with that
// key ("unknown field `PreToolUse`, expected `description` or `hooks`", one
// interactive start on 2026-11-10) and loads no hook from the file.
func oldCodexHooksFile(t *testing.T, extra string) string {
	t.Helper()
	old := filepath.Join(exampleDir(t), "hooks", "anthropic-hook.sh")
	return fmt.Sprintf(`{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":%q,"timeout":30,"statusMessage":"Tool Guard policy check"}]}%s]}`, old, extra)
}

// TestInstallerUpgradesAnOldCodexHooksFile: before the fix, install.sh codex
// added the "hooks" key and left the old top-level key in place.
func TestInstallerUpgradesAnOldCodexHooksFile(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(oldCodexHooksFile(t, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runInstaller(t, home, "codex")
	var got map[string]any
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	for k := range got {
		if k != "hooks" && k != "description" {
			t.Errorf("after an upgrade hooks.json has the top-level key %q; Codex CLI 0.166.0 accepts only description and hooks:\n%s", k, data)
		}
	}
	if !strings.Contains(string(data), filepath.Join(exampleDir(t), "hooks", "codex-hook.sh")) {
		t.Errorf("after an upgrade hooks.json does not name codex-hook.sh:\n%s", data)
	}
	if strings.Contains(string(data), "anthropic-hook.sh") {
		t.Errorf("after an upgrade hooks.json still names the old adapter:\n%s", data)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("install.sh warned although it removed the old key:\n%s", out)
	}
}

// TestInstallerRefusesAForeignTopLevelCodexEntry: Codex CLI 0.166.0 loads no
// hook from a hooks.json with a top-level PreToolUse key. An entry of another
// tool under that key is not the installer's to move, so the installer must
// stop without a success line and without changing the file.
func TestInstallerRefusesAForeignTopLevelCodexEntry(t *testing.T) {
	exampleHooksTg(t)
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	for name, content := range map[string]string{
		"own and foreign entry":  oldCodexHooksFile(t, ",{\"matcher\":\"x\",\"hooks\":[{\"type\":\"command\",\"command\":\"/usr/local/bin/other-hook\"}]}"),
		"foreign entry only":     "{\"PreToolUse\":[{\"matcher\":\"^Bash$\",\"hooks\":[{\"command\":\"/usr/bin/other\"}]}]}",
		"entry without hooks":    "{\"PreToolUse\":[{\"matcher\":\"x\"}]}",
		"top-level key no array": "{\"PreToolUse\":{\"x\":1}}",
	} {
		home := t.TempDir()
		f := filepath.Join(home, ".codex", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "codex")
		cmd.Env = installerEnv(t, home)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: install.sh exited 0:\n%s", name, out)
		}
		if strings.Contains(string(out), "✓ Codex") || strings.Contains(string(out), "Done.") {
			t.Errorf("%s: install.sh printed a success line:\n%s", name, out)
		}
		if !strings.Contains(string(out), "top-level PreToolUse") {
			t.Errorf("%s: install.sh did not name the top-level key:\n%s", name, out)
		}
		if data, _ := os.ReadFile(f); string(data) != content {
			t.Errorf("%s: install.sh changed the file:\n%s", name, data)
		}
		if _, err := os.Stat(f + ".bak-toolguard"); err == nil {
			t.Errorf("%s: install.sh left a backup of a file it did not change", name)
		}
	}
}

// TestUninstallRestoresTheFirstConfig: the backup is taken once. A second
// install must not replace it with a file that already holds the hook.
func TestUninstallRestoresTheFirstConfig(t *testing.T) {
	home := t.TempDir()
	files := map[string]string{
		"claude":      filepath.Join(home, ".claude", "settings.json"),
		"codex":       filepath.Join(home, ".codex", "hooks.json"),
		"antigravity": filepath.Join(home, ".gemini", "config", "hooks.json"),
	}
	for name, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(`{"marker":"first-`+name+`"}`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runInstaller(t, home, "claude", "codex", "antigravity")
	runInstaller(t, home, "claude", "codex", "antigravity")
	runInstaller(t, home, "--uninstall", "claude", "codex", "antigravity")
	for name, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := `{"marker":"first-` + name + `"}` + "\n"; string(data) != want {
			t.Errorf("%s: uninstall after two installs restored %q, want the first file %q", name, data, want)
		}
	}
}

// TestReadmeRepeatRangeMatchesScript: the README states the accepted range of
// TG_VERIFY_REPEAT. The script enforces it with one regular expression.
func TestReadmeRepeatRangeMatchesScript(t *testing.T) {
	script := readRepoFile(t, "examples", "coding-agent-guard", "verify_harnesses.py")
	m := regexp.MustCompile(`re\.fullmatch\(r"\[(\d)-(\d)\]", self\.repeat_text\)`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("verify_harnesses.py no longer checks TG_VERIFY_REPEAT with a one-digit range; update this test")
	}
	want := fmt.Sprintf("from %s to %s", m[1], m[2])
	if !strings.Contains(script, "TG_VERIFY_REPEAT must be a whole number "+want) {
		t.Errorf("the error message of verify_harnesses.py does not say %q", want)
	}
	readme := oneLine(readRepoFile(t, "examples", "coding-agent-guard", "README.md"))
	if !strings.Contains(readme, "`TG_VERIFY_REPEAT` to a number "+want+".") {
		t.Errorf("the example README does not state the range %q for TG_VERIFY_REPEAT", want)
	}
}

// TestReadmeAgyEscalationDefaultMatchesFlag: the wrapper passes
// -antigravity-escalation only when TG_AGY_ESCALATION is set, so the default
// in the README table is the default of the flag.
func TestReadmeAgyEscalationDefaultMatchesFlag(t *testing.T) {
	src := readRepoFile(t, "cmd", "tg", "hook.go")
	m := regexp.MustCompile(`fs\.String\("antigravity-escalation", "(\w+)"`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("hook.go no longer defines -antigravity-escalation this way; update this test")
	}
	wrapper := readRepoFile(t, "examples", "coding-agent-guard", "hooks", "guard-hook.sh")
	if !strings.Contains(wrapper, `[ -n "${TG_AGY_ESCALATION:-}" ]`) {
		t.Fatal("guard-hook.sh no longer passes the flag only when TG_AGY_ESCALATION is set; update this test")
	}
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	row := regexp.MustCompile("(?m)^\\| `TG_AGY_ESCALATION` \\|.*\\| `(\\w+)` \\|$").FindStringSubmatch(readme)
	if row == nil {
		t.Fatal("the example README has no TG_AGY_ESCALATION row with a default")
	}
	if row[1] != m[1] {
		t.Errorf("README gives the default %q for TG_AGY_ESCALATION; the flag default is %q", row[1], m[1])
	}
}

func manifestVersion(t *testing.T, m harnessManifest, prefix string) string {
	t.Helper()
	v := ""
	for _, h := range m.Harnesses {
		if !strings.HasPrefix(h.Configuration, prefix) {
			continue
		}
		if v != "" && v != h.VersionNumber {
			t.Fatalf("the manifest has two versions for %q: %s and %s", prefix, v, h.VersionNumber)
		}
		v = h.VersionNumber
	}
	if v == "" {
		t.Fatalf("the manifest has no harness whose configuration starts with %q", prefix)
	}
	return v
}

// TestMatrixStageVersionsMatchManifest: the sentence that names the one
// version of each harness on which stages ran.
func TestMatrixStageVersionsMatchManifest(t *testing.T) {
	m := loadHarnessManifest(t)
	want := fmt.Sprintf("The stages ran on one version of each harness: Claude Code %s, Codex CLI %s and Antigravity CLI %s.",
		manifestVersion(t, m, "claude"), manifestVersion(t, m, "codex"), manifestVersion(t, m, "agy"))
	if !strings.Contains(oneLine(readRepoFile(t, "docs", "support-matrix.md")), want) {
		t.Errorf("docs/support-matrix.md does not hold the sentence %q", want)
	}
}

// TestMatrixRunSizeMatchesManifest: the stage count and the number of paid
// calls in "Reproducing the run", and the stage count in the script header.
func TestMatrixRunSizeMatchesManifest(t *testing.T) {
	m := loadHarnessManifest(t)
	stages := 0
	for _, h := range m.Harnesses {
		stages += len(h.Stages)
	}
	if m.Repeat != 3 {
		t.Fatalf("the release manifest has repeat %d; the matrix says three times", m.Repeat)
	}
	matrix := oneLine(readRepoFile(t, "docs", "support-matrix.md"))
	got := regexp.MustCompile(`sends each of the (\d+) stages three times, which is about (\d+) paid model calls`).FindStringSubmatch(matrix)
	if got == nil {
		t.Fatal("docs/support-matrix.md no longer states the size of the release run")
	}
	if got[1] != strconv.Itoa(stages) || got[2] != strconv.Itoa(stages*m.Repeat) {
		t.Errorf("the matrix says %s stages and %s calls; the manifest has %d stages and %d calls", got[1], got[2], stages, stages*m.Repeat)
	}
	script := readRepoFile(t, "examples", "coding-agent-guard", "verify_harnesses.py")
	if !strings.Contains(script, fmt.Sprintf("There are %d stages", stages)) {
		t.Errorf("the header of verify_harnesses.py does not say there are %d stages", stages)
	}
}

// TestChangelogAgyFlagProtectionMatchesManifest: the changelog tells an
// operator what the flag --dangerously-skip-permissions leaves them with.
// The "no escalation protection" sentence is allowed only while the manifest
// shows the escalated call running with the flag.
func TestChangelogAgyFlagProtectionMatchesManifest(t *testing.T) {
	m := loadHarnessManifest(t)
	// The stages come from the one Antigravity entry started with the flag.
	// A second entry or a repeated stage ID would let one record hide another.
	const flagged = "agy --dangerously-skip-permissions --print"
	stage := map[string]harnessManifestStage{}
	entries := 0
	for _, h := range m.Harnesses {
		if h.Configuration != flagged {
			continue
		}
		entries++
		if h.ID != "agy" {
			t.Fatalf("manifest: the entry with configuration %q has ID %q, not \"agy\"", flagged, h.ID)
		}
		for _, s := range h.Stages {
			if _, dup := stage[s.ID]; dup {
				t.Fatalf("manifest: the entry with configuration %q has stage %s twice", flagged, s.ID)
			}
			stage[s.ID] = s
		}
	}
	if entries != 1 {
		t.Fatalf("manifest: %d entries with configuration %q; the test needs exactly one", entries, flagged)
	}
	// The deny stages must hold in every run. A run that the verifier counts
	// as worked_around is a held run: the denied call did not run.
	for _, id := range []string{"shell_deny", "escalation_shell_as_deny"} {
		s, ok := stage[id]
		if !ok {
			t.Fatalf("manifest: no stage %s with the flag", id)
		}
		if held := s.Outcomes["blocked"] + s.Outcomes["worked_around"]; s.Result != "PASS" || s.Runs == 0 || held != s.Runs {
			t.Fatalf("manifest: stage %s with the flag has result %q and outcomes %v in %d runs; the changelog sentence needs the call held in every run", id, s.Result, s.Outcomes, s.Runs)
		}
	}
	want := "gets deny protection and no escalation protection unless `TG_ESCALATE_AS=deny` is set."
	has := strings.Contains(oneLine(readRepoFile(t, "CHANGELOG.md")), want)
	// The sentence is a claim about the measured version. It needs a run in
	// which the escalated call ran.
	esc, ok := stage["escalation_shell"]
	if !ok {
		t.Fatal("manifest: no stage escalation_shell with the flag")
	}
	if esc.Outcomes["ran"] == 0 {
		if has {
			t.Errorf("CHANGELOG.md holds the sentence ending %q; in the manifest stage escalation_shell with the flag ran in 0 of %d runs (outcomes %v)",
				want, esc.Runs, esc.Outcomes)
		}
		return
	}
	if !has {
		t.Errorf("CHANGELOG.md does not hold the sentence ending %q", want)
	}
}
