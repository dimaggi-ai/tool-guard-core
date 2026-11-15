package main

// Sentences an operator relies on. The third independent review changed each
// of them to its opposite and the suite still passed. Each sentence is now
// required as written, next to a check of the behaviour it states.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireSentences(t *testing.T, text string, sentences ...string) {
	t.Helper()
	text = oneLine(text)
	for _, s := range sentences {
		if !strings.Contains(text, s) {
			t.Errorf("the document no longer holds the sentence %q; when the behaviour changed, change the sentence and this test together", s)
		}
	}
}

func TestOperatorSentencesMatchBehaviour(t *testing.T) {
	dir := exampleDir(t)
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	changelog := readRepoFile(t, "CHANGELOG.md")
	matrix := readRepoFile(t, "docs", "support-matrix.md")

	// An escalated command: the shell policy escalates an outbound git push.
	want := map[string]string{"claude": "ask", "codex": "deny", "antigravity": "force_ask"}
	for harness, wrapper := range exampleWrappers {
		out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), t.TempDir(), exampleShellPayload(harness, "git push origin main"))
		if got, _ := exampleDecision(t, out); got != want[harness] {
			t.Fatalf("%s wrapper returned %q for an escalated command, want %q", harness, got, want[harness])
		}
	}
	requireSentences(t, readme,
		"The Claude Code and Antigravity CLI wrappers return a request for approval. The Codex wrapper returns a denial.",
		"The first returns an escalation as a denial. The second returns it as `force_ask`.")
	requireSentences(t, changelog, "The Codex wrapper of the example sets `deny`.")

	// A missing tg binary: the wrapper prints a deny.
	for harness, wrapper := range exampleWrappers {
		out := runExampleHook(t, filepath.Join(dir, "hooks", wrapper), t.TempDir(), exampleShellPayload(harness, "ls"),
			"TG_BIN="+filepath.Join(t.TempDir(), "no-such-tg"))
		if got, _ := exampleDecision(t, out); got != "deny" {
			t.Fatalf("%s wrapper returned %q without a tg binary, want deny", harness, got)
		}
	}
	requireSentences(t, readme, "or `tg` prints no decision, it prints a deny.")

	// TG_PROTECT_BASELINE=0 keeps the protect-paths file and drops the rest.
	home := t.TempDir()
	extra := filepath.Join(t.TempDir(), "extra.txt")
	if err := os.MkdirAll(filepath.Join(home, ".tool-guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".tool-guard", "protect-paths"), []byte(extra+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(dir, "hooks", exampleWrappers["claude"])
	for command, wantDecision := range map[string]string{
		"echo x > " + extra:                                  "deny",
		"echo x > " + home + "/.claude/settings.json":        "allow",
		"echo x > " + home + "/.tool-guard/hook-audit.jsonl": "allow",
	} {
		out := runExampleHook(t, claude, home, exampleShellPayload("claude", command), "TG_PROTECT_BASELINE=0")
		if got, _ := exampleDecision(t, out); got != wantDecision {
			t.Fatalf("TG_PROTECT_BASELINE=0, %s: decision = %q, want %q", command, got, wantDecision)
		}
	}
	requireSentences(t, readme, "`TG_PROTECT_BASELINE=0` turns off all of these except the paths in the `protect-paths` file.")

	// The three config files the wrapper protects, and the backup suffix.
	wrapper := readRepoFile(t, "examples", "coding-agent-guard", "hooks", "guard-hook.sh")
	for _, line := range []string{
		`protect+=("${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json")`,
		`protect+=("${CODEX_HOME:-$HOME/.codex}/hooks.json")`,
		`protect+=("$HOME/.gemini/config/hooks.json")`,
	} {
		if !strings.Contains(wrapper, line) {
			t.Fatalf("guard-hook.sh no longer holds %s; update the changelog sentence and this test", line)
		}
	}
	if n := strings.Count(wrapper, "protect+=(\""); n != 7 {
		t.Fatalf("guard-hook.sh adds protected paths in %d lines, want 7; check the documented list", n)
	}
	requireSentences(t, changelog, "to three harness config files: `~/.claude/settings.json`, `~/.codex/hooks.json` and `~/.gemini/config/hooks.json`.")
	installer := readRepoFile(t, "examples", "coding-agent-guard", "install.sh")
	if !strings.Contains(installer, `cp -p "$1" "$1.bak-toolguard"`) {
		t.Fatal("install.sh no longer writes a .bak-toolguard copy; update the README sentence and this test")
	}
	requireSentences(t, readme, "it copies the file to a file with the suffix `.bak-toolguard` next to it.")

	// apply_patch: the corpus cases hold the reading of the patch text.
	for _, name := range []string{
		"codex0_166_0_apply_patch_new_file_allowed",
		"codex_apply_patch_system_path_denied",
		"codex_apply_patch_protected_path_denied",
		"codex_apply_patch_move_to_protected_denied",
		"codex_apply_patch_second_file_protected_denied",
		"codex_apply_patch_private_key_denied",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "hookconformance", name+".json")); err != nil {
			t.Fatalf("the corpus case %s is gone: %v", name, err)
		}
		if !strings.Contains(changelog, "`"+name+"`") {
			t.Errorf("CHANGELOG.md no longer names the corpus case %s", name)
		}
	}
	requireSentences(t, changelog,
		"`tg hook` now reads the files from the patch text,",
		"A call that names more than 64 files is denied.")
	// What the changelog says about a harness run of the new reading follows
	// the run records of the release manifest. A run counts when its own
	// record names apply_patch: the allowed file was written, or the call for
	// the protected file was blocked. The stage summary names one tool for
	// all runs, so it is not used.
	//   every run of both stages counts: "The release run measured ..." with
	//     the version and the counts is required;
	//   no run of the allowed write counts: "No harness run has measured ..."
	//     is required;
	//   otherwise neither sentence is true and both are rejected.
	const notMeasured, measured = "No harness run has measured the new reading:", "The release run measured the new reading:"
	patchStages := map[string]harnessManifestStage{}
	for _, h := range loadHarnessManifest(t).Harnesses {
		if h.ID != "codex-cli" || h.Configuration != "codex exec" {
			continue
		}
		for _, s := range h.Stages {
			if _, dup := patchStages[s.ID]; dup {
				t.Fatalf("manifest: stage %s of codex exec is there twice", s.ID)
			}
			patchStages[s.ID] = s
		}
	}
	patchRuns := func(id, outcome string) (int, int) {
		s, ok := patchStages[id]
		if !ok {
			t.Fatalf("manifest: no stage %s for codex exec", id)
		}
		n := 0
		for _, r := range s.Records {
			if r.Tool == "apply_patch" && r.Outcome == outcome {
				n++
			}
		}
		if len(s.Records) != 0 && len(s.Records) != s.Runs {
			t.Fatalf("manifest: stage %s of codex exec has %d run records for %d runs", id, len(s.Records), s.Runs)
		}
		return n, s.Runs
	}
	wrote, writeRuns := patchRuns("write_tool_allow_control", "ran")
	held, denyRuns := patchRuns("write_tool_deny", "blocked")
	has := func(sentence string) bool { return strings.Contains(oneLine(changelog), sentence) }
	switch {
	case writeRuns > 0 && wrote == writeRuns && denyRuns > 0 && held == denyRuns:
		requireSentences(t, changelog, measured, fmt.Sprintf(
			"Codex CLI %s wrote the allowed file with `apply_patch` in %d of %d runs, and the call for the protected file was blocked in %d of %d runs.",
			manifestVersion(t, loadHarnessManifest(t), "codex"), wrote, writeRuns, held, denyRuns))
		if has(notMeasured) {
			t.Errorf("CHANGELOG.md holds the sentence %q; in the release manifest every run measured the reading", notMeasured)
		}
	case wrote == 0:
		requireSentences(t, changelog, notMeasured)
		if has(measured) {
			t.Errorf("CHANGELOG.md holds the sentence %q; in the release manifest no run wrote the allowed file with apply_patch", measured)
		}
	default:
		for _, sentence := range []string{notMeasured, measured} {
			if has(sentence) {
				t.Errorf("CHANGELOG.md holds the sentence %q; the release manifest measured the reading in some runs only (allowed write %d of %d, protected write blocked %d of %d)",
					sentence, wrote, writeRuns, held, denyRuns)
			}
		}
	}
	if maxApplyPatchTargets != 64 {
		t.Fatalf("maxApplyPatchTargets is %d; CHANGELOG.md says 64", maxApplyPatchTargets)
	}

	// The trust flag of the release run.
	m := loadHarnessManifest(t)
	untrusted := false
	for _, h := range m.Harnesses {
		for _, s := range h.Stages {
			if s.ID == "untrusted_hook" && s.Outcome == "ran_without_hook" {
				untrusted = true
			}
		}
	}
	if !untrusted {
		t.Fatal("the manifest no longer shows that Codex ran a command without calling an untrusted hook")
	}
	requireSentences(t, matrix,
		"The flag `--dangerously-bypass-hook-trust` makes Codex call the hook without the trust step.",
		"No stage accepted the hook at the interactive prompt, so the run does not show what Codex does after that step.")
}
