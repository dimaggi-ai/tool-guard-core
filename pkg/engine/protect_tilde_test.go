package engine

import (
	"encoding/json"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestProtectedPathTildeAndShellDashC pins two shell forms the protected-path
// check missed before 0.9.0: a path written with a leading tilde, and a
// command passed to a shell with -c.
func TestProtectedPathTildeAndShellDashC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	cases := []struct {
		cmd  string
		want bool
	}{
		{"echo x > ~/.claude/settings.json", true},
		{"cp /tmp/a ~/.claude/settings.json", true},
		{"echo x >> ~/.tool-guard/protect-paths", true},
		{"rm -rf ~", true}, // the home directory is above the protected paths
		{"rm -rf ~/.tool-guard", true},
		{"dd if=/dev/null of=~/.claude/settings.json", true},
		{"echo x > ~other/.claude/settings.json", true},
		{"rm ~+/f", true},
		{"echo x > ~/notes.txt", false},
		{"cat ~/.claude/settings.json", false},
		{"ls ~other", false},
		{"bash -c 'echo x > " + home + "/.claude/settings.json'", true},
		{"sh -c \"cp /tmp/a " + home + "/.claude/settings.json\"", true},
		{"bash -lc 'echo x > ~/.claude/settings.json'", true},
		{"bash -c \"echo $USER > ~/.claude/settings.json\"", true},
		{"bash -c 'echo hello'", false},
		{"bash -c \"echo $USER\"", false},
		{"bash script.sh -c", false},
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
