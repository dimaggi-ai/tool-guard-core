package engine

import (
	"encoding/json"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestProtectedPathReview4Forms pins the shell forms the fourth independent
// review (2026-11-10) ran in a real bash and found allowed: each changed a
// protected file. The benign commands next to them must stay allowed.
func TestProtectedPathReview4Forms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := home + "/.claude/settings.json"
	prefixes := []string{cfg, home + "/.codex/hooks.json", home + "/.tool-guard"}
	cases := []struct {
		cmd  string
		want bool
	}{
		// The -c flag in an option cluster, and options after it.
		{"bash -ce 'echo x > ~/.claude/settings.json'", true},
		{"bash -cx 'echo x > ~/.claude/settings.json'", true},
		{"bash -c -e 'echo x > ~/.claude/settings.json'", true},
		{"bash -c -x 'echo x > ~/.claude/settings.json'", true},
		{"bash -c -- 'echo x > ~/.claude/settings.json'", true},
		{"sh -c -- 'echo x > ~/.claude/settings.json'", true},
		{"bash -c -o pipefail 'echo x > ~/.claude/settings.json'", true},
		{"bash -o pipefail -c 'echo x > ~/.claude/settings.json'", true},
		{"bash --norc -c 'rm ~/.claude/settings.json'", true},
		{"/bin/bash -ec 'rm ~/.claude/settings.json'", true},
		// An expansion of the outer command inside inner quotes.
		{"bash -c \"echo x > '$HOME'/.claude/settings.json\"", true},
		{"bash -c \"rm '$HOME/.claude/settings.json'\"", true},
		{"bash -c \"echo x > '$HOME/.claude/settings.json'\"", true},
		{"bash -c $'rm ~/.claude/settings.json'", true},
		{"bash -c \"$CMD\"", true},
		{"bash -c \"rm -f $TMPDIR/x\"", true},
		// A write through the directory of the protected file.
		{"cp settings.json ~/.claude/", true},
		{"cp -t ~/.claude settings.json", true},
		{"mv settings.json ~/.claude", true},
		{"cp --target-directory=" + home + "/.claude settings.json", true},
		{"install -m 600 hooks.json " + home + "/.codex", true},
		{"mv ~/.claude ~/.claude-old", true},
		{"chmod 000 ~/.claude", true},
		{"ln -sfn /tmp/evil ~/.claude", true},
		{"mv ~/.codex /tmp/y", true},
		{"rm -rf " + home, true},
		// Benign commands.
		{"bash -c 'echo hi'", false},
		{"bash -lc 'npm test'", false},
		{"bash -c \"echo $HOME\"", false},
		{"bash -c \"cd $DIR && npm test\"", false},
		{"bash -c 'echo x > ~/notes.txt'", false},
		// Since the name rule (2026-11-10) a command whose text names a
		// protected path is denied unless it only reads.
		{"bash script.sh -c 'rm ~/.claude/settings.json'", true},
		{"bash script.sh -c 'rm ~/notes.txt'", false},
		{"cp notes.txt ~/", false},
		{"cp settings.json ~/project/", false},
		{"mv a.txt ~/docs", false},
		{"mkdir -p ~/.claude", false},
		{"rm ~/tmp/x", false},
		{"chmod +x ~/bin/tool", false},
		{"gcc -c main.c", false},
		{"python3 -c 'print(1)'", false},
	}
	for _, c := range cases {
		params, _ := json.Marshal(map[string]string{"command": c.cmd})
		env := &domain.ActionEnvelope{ToolName: "bash", Parameters: params}
		got, reason := ViolatesProtectedPaths(env, prefixes)
		if got != c.want {
			t.Errorf("%q: denied = %v (%s), want %v", c.cmd, got, reason, c.want)
		}
	}
}
