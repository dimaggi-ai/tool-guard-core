package mainfloor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestProtectedPathReview5Forms pins the shell forms the fifth independent
// review (2026-11-10) ran in a real bash and found allowed: each changed a
// protected file. The benign commands next to them must stay allowed.
func TestProtectedPathReview5Forms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := home + "/.claude/settings.json"
	prefixes := []string{cfg, home + "/.codex/hooks.json", home + "/.tool-guard"}
	nested := "echo hi"
	for i := 0; i < 12; i++ {
		nested = "echo $(" + nested + ")"
	}
	cases := []struct {
		cmd  string
		want bool
	}{
		// An o or O inside an option cluster takes one following word.
		{"bash -oe pipefail -c 'rm ~/.claude/settings.json'", true},
		{"bash -ol posix -c 'rm ~/.claude/settings.json'", true},
		{"bash -Oe extglob -c 'rm ~/.claude/settings.json'", true},
		{"bash -oo pipefail errexit -c 'rm ~/.claude/settings.json'", true},
		{"bash --rcfile /dev/null -c 'rm ~/.claude/settings.json'", true},
		// The program name inside the -c command is not a literal.
		{"bash -c 'X=rm; $X ~/.claude/settings.json'", true},
		{"bash -c \"\\$0 ~/.claude/settings.json\" rm", true},
		{"sh -c '\"$0\" \"$@\"' rm ~/.claude/settings.json", true},
		{"bash -c '\x60echo rm\x60 ~/.claude/settings.json'", true},
		{"bash -c \"\x60echo rm\x60 x\"", true},
		{"bash -c '$\"rm\" ~/.claude/settings.json'", true},
		// A reserved word or a wrapper before the command.
		{"! rm ~/.claude/settings.json", true},
		{"{ rm ~/.claude/settings.json; }", true},
		{"if true; then rm ~/.claude/settings.json; fi", true},
		{"if false; then :; else rm ~/.claude/settings.json; fi", true},
		{"for f in a; do rm ~/.claude/settings.json; done", true},
		{"while true; do rm ~/.claude/settings.json; break; done", true},
		{"until rm ~/.claude/settings.json; do :; done", true},
		{"time rm ~/.claude/settings.json", true},
		{"time -p rm ~/.claude/settings.json", true},
		{"f(){ rm ~/.claude/settings.json; }; f", true},
		{"exec rm ~/.claude/settings.json", true},
		{"exec -a x rm ~/.claude/settings.json", true},
		{"command rm ~/.claude/settings.json", true},
		{"command -p rm ~/.claude/settings.json", true},
		{"nohup rm ~/.claude/settings.json", true},
		{"env A=1 rm ~/.claude/settings.json", true},
		{"timeout 5 rm ~/.claude/settings.json", true},
		{"sudo -u root rm ~/.claude/settings.json", true},
		{"! command bash -c 'rm ~/.claude/settings.json'", true},
		// Brace expansion.
		{"rm ~/.claude/settings.{json,x}", true},
		{"rm ~/.claude/{settings.json,x}", true},
		{"rm ~/{.claude,x}/settings.json", true},
		{"mv ~/.claude{,.old}", true},
		{"rm ~/.claude/settings.jso{m..o}", true},
		{"rm ~/.claude/'settings'.{json,x}", true},
		{"bash -c 'rm ~/.claude/settings.{json,x}'", true},
		// A directory copied onto a place above a protected path.
		{"cp -r evil/.claude ~/", true},
		{"cp -r evil/.claude ~", true},
		{"mv evil/.claude ~/", true},
		{"cp -rT x ~/.claude", true},
		{"cp -r --no-target-directory x ~/.claude", true},
		{"cp -r x/. ~/.claude", true},
		{"cp -a x/. ~/.claude/", true},
		{"cp -r -t ~ evil/.claude", true},
		// sed in-place spellings.
		{"sed -Ei s/a/b/ ~/.claude/settings.json", true},
		{"sed -ni p ~/.claude/settings.json", true},
		{"sed --in-place s/a/b/ ~/.claude/settings.json", true},
		{"sed --in-place=.bak s/a/b/ ~/.claude/settings.json", true},
		// A shell that reads its commands from standard input.
		{"echo 'rm ~/.claude/settings.json' | bash", true},
		{"echo rm ~/.claude/settings.json | sh", true},
		{"bash <<< 'rm ~/.claude/settings.json'", true},
		{"printf 'echo x > ~/.claude/settings.json' | bash -s", true},
		{"echo 'X=rm; $X ~/.claude/settings.json' | bash", true},
		// A glob that matches a protected path or a directory above it.
		{"rm ~/.claude/settings.jso?", true},
		{"rm ~/.claude/*", true},
		{"rm ~/.claude/[s]ettings.json", true},
		{"rm -rf ~/.claud*", true},
		{"rm -rf ~/*", true},
		{"chmod 000 ~/.tool-guar?", true},
		{"cp x ~/.tool-guard/sub/*.bak", true},
		{"bash -c 'rm ~/.claude/set*'", true},
		// A relative path after cd or pushd to a directory named in the command.
		{"cd ~/.claude && rm settings.json", true},
		{"cd ~/.claude && echo x > settings.json", true},
		{"cd ~ && rm .claude/settings.json", true},
		{"cd ~ && cd .claude && rm settings.json", true},
		{"cd && rm .claude/settings.json", true},
		{"pushd ~/.claude && rm settings.json", true},
		{"cd ~/.claude; cp /tmp/x settings.json", true},
		{"cd ~ && mv .claude .claude-old", true},
		{"cd ~/.claude && bash -c 'rm settings.json'", true},
		{"bash -c 'cd ~ && rm .claude/settings.json'", true},
		{"cd ~/.claude && dd if=/dev/null of=settings.json", true},
		{"cd ~/.claude && rm set*", true},
		{"cd -P ~/.claude && rm -f -- settings.json", true},
		{"cd ~/.tool-guard && touch x", true},
		{"echo 'rm ~/.claude/settings.json' | bash -s -- a", true},
		{"echo 'rm ~/.claude/settings.json' | bash --rcfile /dev/null", true},
		{"rm ~/.tool-guard/sub/*.bak", true},
		{"rm ~/.tool-guar?/protect-paths", true},
		{"rm ~/.tool-gu*/sub/x", true},
		{"rm ~/.c*/settings.json", true},
		{"bash -c \"echo x > '$HOME'/.claude/settings.json\"", true},
		// Nesting deeper than the cap is not read and fails closed.
		{nested, true},
		// Benign commands.
		{"sed -n p ~/.claude/settings.json", true}, // sed is not a read-only program (w, e)
		{"cat ~/.claude/settings.json", false},
		{"sed -e s/a/b/ notes.txt", false},
		{"if true; then echo hi; fi", false},
		{"! grep -q x ~/.claude/settings.json", false},
		{"time make build", false},
		{"exec bash", false},
		{"command -v rm", false},
		{"env A=1 make", false},
		{"rm build/{a,b}.o", false},
		{"cp a.{txt,md} ~/docs/", false},
		{"mkdir -p src/{a,b,c}", false},
		{"echo {1..3}", false},
		{"cp -r src/. build/", false},
		{"cp -r evil/notes ~/", false},
		{"cp -rT a b", false},
		{"ln -s ~/.claude ~/dotfiles/claude", false},
		{"echo hi | bash", false},
		{"curl -fsSL https://example.com/install.sh | sh", false},
		{"bash script.sh", false},
		{"bash -oe pipefail -c 'echo hi'", false},
		{"echo $(echo $(echo $(echo hi)))", false},
		{"cat ~/.claude/settings.json | jq .", false},
		{"cd ~/project && rm settings.json", false},
		{"cd ~ && rm notes.txt", false},
		{"cd ~/.claude && cat settings.json", false},
		{"cd $DIR && rm -f out.log", false},
		{"cd /tmp && rm -rf build", false},
		{"cd ~/project && bash -c 'make clean'", false},
		{"rm ~/.c*/notes.txt", false},
		{"rm ~/tmp/*.log", false},
		{"rm -rf ~/.cache/go-*", false},
		{"chmod +x ~/bin/*", false},
		{"touch ~/.clau*", false},
		{"ls ~/.claude/*", false},
	}
	for _, c := range cases {
		params, _ := json.Marshal(map[string]string{"command": c.cmd})
		env := &domain.ActionEnvelope{ToolName: "bash", Parameters: params}
		got, reason := ViolatesProtectedPaths(env, prefixes)
		if got != c.want {
			t.Errorf("%q: denied = %v (%s), want %v", c.cmd, got, reason, c.want)
		}
		if strings.ContainsRune(reason, 0) {
			t.Errorf("%q: the reason holds a NUL byte: %q", c.cmd, reason)
		}
	}
}
