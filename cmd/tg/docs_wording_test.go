package main

// Wording pins. Each banned phrase said something that the code or a measured
// run contradicts. Each required phrase names a file or a setting that a
// reader of the example needs.

import (
	"strings"
	"testing"
)

func TestDocsWordingBans(t *testing.T) {
	bans := []struct {
		file   []string
		phrase string
		why    string
	}{
		{[]string{"policies", "coding_agent_secret_egress.yaml"}, "opt-in", "the policy is active whenever its file is loaded"},
		{[]string{"CHANGELOG.md"}, "so this cannot drift silently", "verify-harnesses.sh runs only when a maintainer starts it"},
		{[]string{"CHANGELOG.md"}, "one of the exact hosts", "in a shell command one listed URL anywhere satisfies the carve-out"},
		{[]string{"CHANGELOG.md"}, "\"Opt-in\" here means", "the two policies are active whenever their directory is loaded"},
		{[]string{"CHANGELOG.md"}, "`provenance.json`", "the verification script writes manifest.json"},
		{[]string{"CHANGELOG.md"}, "all blocked a write to a `-protect-path` target", "measured results belong in docs/support-matrix.md, which a test renders from the manifest"},
		{[]string{"examples", "coding-agent-guard", "README.md"}, "held for a human", "what a harness does with an escalation is measured per harness in docs/support-matrix.md"},
		{[]string{"examples", "coding-agent-guard", "README.md"}, "TG_FAIL=open", "the installed hook does not read TG_FAIL"},
		{[]string{"examples", "coding-agent-guard", "run.sh"}, "Claude Code honours it", "run.sh prints hook decisions; harness behaviour is in docs/support-matrix.md"},
		{[]string{"README.md"}, "verified end to end against real installs", "the matrix states what was measured; the README must not summarise it"},
		{[]string{"README.md"}, "`./verify-harnesses.sh` proves", "the verification script measures; the matrix reports"},
		{[]string{"docs", "getting-started.md"}, "alternative to the hand-rolled shell", "install.sh wires tg hook itself"},
	}
	for _, b := range bans {
		if strings.Contains(readRepoFile(t, b.file...), b.phrase) {
			t.Errorf("%s still contains %q: %s", strings.Join(b.file, "/"), b.phrase, b.why)
		}
	}
}

func TestExampleReadmeDescribesTheInstalledWiring(t *testing.T) {
	text := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	for _, want := range []string{
		"hooks/claude-code-hook.sh", "hooks/codex-hook.sh", "hooks/antigravity-cli-hook.sh",
		"tg hook", "docs/support-matrix.md", "TG_ESCALATE_AS", "TG_PROTECT_BASELINE",
		"verify-harnesses.sh", "hooks/legacy/", "accept the hook",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("examples/coding-agent-guard/README.md does not mention %q", want)
		}
	}
}
