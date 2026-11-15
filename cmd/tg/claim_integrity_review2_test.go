package main

// Tests added after the second independent review of the 0.9.0 claims
// (2026-11-10). Each one closes a mutation that the suite accepted before.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestInstallerWritesWhatTheTemplatesHold runs install.sh in an empty home
// directory and compares each config file with its template. The release run
// uses the templates and install.sh builds its own JSON with jq, so without
// this test the two could differ. Before it, an installer that wrote the
// matcher "Bash" for Claude Code or "run_command" for Antigravity CLI passed.
func TestInstallerWritesWhatTheTemplatesHold(t *testing.T) {
	exampleHooksTg(t)
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("install.sh needs jq; install it so this test can run: %v", err)
	}
	dir := exampleDir(t)
	home := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(dir, "install.sh"), "claude", "codex", "antigravity")
	cmd.Env = installerEnv(t, home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	for template, installed := range map[string]string{
		"claude-code.settings.json": filepath.Join(home, ".claude", "settings.json"),
		"codex.hooks.json":          filepath.Join(home, ".codex", "hooks.json"),
		"antigravity.hooks.json":    filepath.Join(home, ".gemini", "config", "hooks.json"),
	} {
		raw := readRepoFile(t, "examples", "coding-agent-guard", "config", template)
		raw = strings.ReplaceAll(raw, "__HOOK_DIR__", filepath.Join(dir, "hooks"))
		var want map[string]any
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatalf("%s: %v", template, err)
		}
		delete(want, "_comment")
		got := map[string]any{}
		data, err := os.ReadFile(installed)
		if err != nil {
			t.Errorf("install.sh did not write %s: %v", installed, err)
			continue
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Errorf("%s: %v", installed, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("install.sh wrote %s, which differs from config/%s without _comment.\ninstalled: %s\ntemplate:  %v",
				installed, template, data, want)
		}
	}
}

// TestMatrixNamesEveryHarnessFlagOfTheRun reads the command lines that
// verify_harnesses.py starts and requires docs/support-matrix.md to name every
// flag in them. The column "Started as" holds a short name only. Before this
// test the matrix did not say that the Codex stages ran with
// --dangerously-bypass-hook-trust.
func TestMatrixNamesEveryHarnessFlagOfTheRun(t *testing.T) {
	script := readRepoFile(t, "examples", "coding-agent-guard", "verify_harnesses.py")
	matrix := readRepoFile(t, "docs", "support-matrix.md")
	argv := regexp.MustCompile(`(?s)"argv": lambda p: \[(.*?)\],\s+"stages"`).FindAllStringSubmatch(script, -1)
	if len(argv) < 5 {
		t.Fatalf("found %d command lines in verify_harnesses.py, want at least 5", len(argv))
	}
	seen := map[string]bool{}
	for _, m := range argv {
		for _, flag := range regexp.MustCompile(`--[A-Za-z][A-Za-z-]*`).FindAllString(m[1], -1) {
			if seen[flag] {
				continue
			}
			seen[flag] = true
			if !strings.Contains(matrix, flag) {
				t.Errorf("verify_harnesses.py starts a harness with %s and docs/support-matrix.md does not name that flag", flag)
			}
		}
	}
	if !seen["--dangerously-bypass-hook-trust"] && strings.Contains(matrix, "--dangerously-bypass-hook-trust") {
		t.Error("docs/support-matrix.md names --dangerously-bypass-hook-trust and verify_harnesses.py no longer uses it")
	}
}

// TestVerifiedRowVersionsHaveARunOrSayPayloadOnly checks every version in a
// row with the status verified. A version with no run in the manifest must be
// named in a paragraph that says no stage ran on it.
func TestVerifiedRowVersionsHaveARunOrSayPayloadOnly(t *testing.T) {
	matrix := readRepoFile(t, "docs", "support-matrix.md")
	m := loadHarnessManifest(t)
	var paragraphs []string
	for _, p := range strings.Split(matrix, "\n\n") {
		paragraphs = append(paragraphs, strings.Split(p, "\n- ")...)
	}
	checked := 0
	for _, line := range strings.Split(matrix, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 5 || strings.TrimSpace(cells[3]) != "verified" {
			continue
		}
		for _, version := range strings.Split(cells[2], ",") {
			version = strings.TrimSpace(version)
			checked++
			hasRun := false
			for _, h := range m.Harnesses {
				hasRun = hasRun || strings.Contains(" "+h.Version+" ", " "+version+" ")
			}
			if hasRun {
				continue
			}
			said := false
			for _, p := range paragraphs {
				p = strings.Join(strings.Fields(p), " ")
				said = said || (strings.Contains(p, version) && strings.Contains(p, "no stage ran"))
			}
			if !said {
				t.Errorf("row %q lists version %s as verified; the manifest has no run of it and no paragraph says that no stage ran on it",
					strings.TrimSpace(cells[1]), version)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("checked %d versions in verified rows, want at least 5", checked)
	}
}

// TestChangelogStatesTheVariantLimit ties the number in CHANGELOG.md to the
// constant. Before this test either one could change alone.
func TestChangelogStatesTheVariantLimit(t *testing.T) {
	m := regexp.MustCompile(`evaluates at most (\d+) extra values`).FindStringSubmatch(readRepoFile(t, "CHANGELOG.md"))
	if m == nil {
		t.Fatal("CHANGELOG.md no longer has the sentence \"evaluates at most N extra values\"")
	}
	if n, _ := strconv.Atoi(m[1]); n != maxHookParamVariants {
		t.Errorf("CHANGELOG.md says at most %d extra values; maxHookParamVariants is %d", n, maxHookParamVariants)
	}
}

// TestChangelogAntigravityRunCountsMatchManifest compares the two run counts
// that CHANGELOG.md gives for Antigravity CLI started with
// --dangerously-skip-permissions with the manifest. The sentence names a
// version. When the manifest holds a run of another version, the sentence must
// say "an earlier run", not "the release run", and its version and counts are
// compared with docs/evidence/harness-manifest-24eafd6.json: the retained
// manifest of the run of 2026-11-10 on commit 24eafd647ce3.
func TestChangelogAntigravityRunCountsMatchManifest(t *testing.T) {
	text := strings.Join(strings.Fields(readRepoFile(t, "CHANGELOG.md")), " ")
	re := regexp.MustCompile("In (the release run|an earlier run) on Antigravity CLI (\\d+\\.\\d+\\.\\d+), started with `--dangerously-skip-permissions` in headless print mode, " +
		"a `run_command` call ran after the hook answered `ask` in (\\d+) of (\\d+) runs and after it answered `force_ask` in (\\d+) of (\\d+) runs")
	got := re.FindStringSubmatch(text)
	if got == nil {
		t.Fatal("CHANGELOG.md no longer has the sentence with the two Antigravity run counts")
	}
	manifest := loadHarnessManifest(t)
	measured := manifestVersion(t, manifest, "agy")
	if got[2] != measured {
		if got[1] != "an earlier run" {
			t.Fatalf("CHANGELOG.md calls the run on Antigravity CLI %s the release run; the manifest holds a run of %s", got[2], measured)
		}
		manifest = loadHarnessManifestFile(t, "harness-manifest-24eafd6.json")
		if earlier := manifestVersion(t, manifest, "agy"); got[2] != earlier {
			t.Fatalf("CHANGELOG.md gives counts for an earlier run on Antigravity CLI %s; the retained earlier manifest holds a run of %s", got[2], earlier)
		}
	} else if got[1] != "the release run" {
		t.Fatalf("CHANGELOG.md calls the run on Antigravity CLI %s an earlier run; the manifest holds that run", got[2])
	}
	got = append(got[:1], got[3:]...)
	want := map[string][2]int{}
	for _, h := range manifest.Harnesses {
		if h.Configuration != "agy --dangerously-skip-permissions --print" {
			continue
		}
		for _, s := range h.Stages {
			want[s.ID] = [2]int{s.Outcomes["ran"], s.Runs}
		}
	}
	for i, stage := range []string{"escalation_shell_plain_ask", "escalation_shell"} {
		ran, _ := strconv.Atoi(got[1+2*i])
		runs, _ := strconv.Atoi(got[2+2*i])
		if w, ok := want[stage]; !ok || w != [2]int{ran, runs} {
			t.Errorf("CHANGELOG.md says stage %s ran in %d of %d runs; the manifest says %v", stage, ran, runs, want[stage])
		}
	}
}

// TestMatrixProseOutsideTheBlockStatesNoEscalationOutcome applies the rule of
// TestOperatorDocsDoNotStateEscalationOutcomes to docs/support-matrix.md
// outside the generated block. The block is the only place for such a
// statement. A sentence that has the word "not" is a limit and is accepted.
func TestMatrixProseOutsideTheBlockStatesNoEscalationOutcome(t *testing.T) {
	matrix := readRepoFile(t, "docs", "support-matrix.md")
	const begin, end = "<!-- harness-evidence:begin -->", "<!-- harness-evidence:end -->"
	i, j := strings.Index(matrix, begin), strings.Index(matrix, end)
	if i < 0 || j < i {
		t.Fatal("docs/support-matrix.md has no harness-evidence block")
	}
	prose := matrix[:i] + matrix[j+len(end):]
	for _, p := range strings.Split(prose, "\n\n") {
		for _, item := range strings.Split(p, "\n- ") {
			if strings.HasPrefix(strings.TrimSpace(item), "|") {
				continue
			}
			for _, sentence := range strings.Split(strings.Join(strings.Fields(item), " "), ". ") {
				if harnessWordRe.MatchString(sentence) && approvalWordRe.MatchString(sentence) && stopWordRe.MatchString(sentence) &&
					!regexp.MustCompile(`(?i)\bnot\b`).MatchString(sentence) {
					t.Errorf("docs/support-matrix.md states an escalation outcome outside the generated block: %s", sentence)
				}
			}
		}
	}
}

// TestExampleReadmeProtectedPathsAndDefaultsMatchWrapper compares two
// statements of the example README with hooks/guard-hook.sh: which config
// files are protected, and the default of TG_ESCALATE_AS for each agent.
func TestExampleReadmeProtectedPathsAndDefaultsMatchWrapper(t *testing.T) {
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	wrapper := readRepoFile(t, "examples", "coding-agent-guard", "hooks", "guard-hook.sh")
	configs := regexp.MustCompile(`(?m)^\s*protect\+=\("[^"]*\.(json|toml)"\)$`).FindAllString(wrapper, -1)
	if len(configs) != 3 {
		t.Errorf("guard-hook.sh protects %d config files; the example README says three", len(configs))
	}
	i := strings.Index(readme, "## Protected paths")
	j := strings.Index(readme, "## Environment variables")
	if i < 0 || j < i {
		t.Fatal("example README lost the section Protected paths or Environment variables")
	}
	section := readme[i:j]
	if !strings.Contains(section, "the three config files in the table above,\n") {
		t.Error("example README no longer lists exactly \"the three config files in the table above,\" as protected")
	}
	for _, tok := range regexp.MustCompile("`[^`]+`").FindAllString(section, -1) {
		// A token with a blank is a command example, not a path:
		// TestExampleHookDeniesReview6Forms runs those.
		if strings.Contains(tok, " ") {
			continue
		}
		if (strings.Contains(tok, ".json") || strings.Contains(tok, ".toml")) && !strings.Contains(wrapper, strings.Trim(tok, "`~")) {
			t.Errorf("example README lists %s as protected and guard-hook.sh does not protect it", tok)
		}
	}
	if strings.Count(wrapper, "${TG_ESCALATE_AS:-ask}") != 2 || strings.Count(wrapper, "${TG_ESCALATE_AS:-deny}") != 1 ||
		!regexp.MustCompile(`(?s)codex\)\s+dialect=claude\s+escalate="\$\{TG_ESCALATE_AS:-deny\}"`).MatchString(wrapper) {
		t.Error("guard-hook.sh no longer defaults TG_ESCALATE_AS to deny for codex and ask for the other two")
	}
	if !strings.Contains(readme, "| `TG_ESCALATE_AS` | `ask` or `deny` | `deny` for Codex, `ask` for the other two |") {
		t.Error("example README no longer states the TG_ESCALATE_AS defaults: deny for Codex, ask for the other two")
	}
}

// installerEnv is the environment for a run of install.sh in a temporary home
// directory. install.sh builds bin/tg when the file is missing. With HOME
// alone that build put a read-only Go module cache into the temporary
// directory, and the test failed when it could not remove the directory. The
// build now uses the module cache and build cache of the test run.
func installerEnv(t *testing.T, home string) []string {
	t.Helper()
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TG_BIN=" + exampleHooksTg(t)}
	out, err := exec.Command("go", "env", "GOMODCACHE", "GOCACHE").Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	dirs := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(dirs) != 2 {
		t.Fatalf("go env printed %q, want two lines", out)
	}
	return append(env, "GOMODCACHE="+dirs[0], "GOCACHE="+dirs[1])
}
