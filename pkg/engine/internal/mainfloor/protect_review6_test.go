package mainfloor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// review6Cases reads testdata/review6_cases.txt. The file holds the commands
// of the sixth independent review (2026-11-10). A line "---" separates two
// cases. The first line of a case is "deny" or "pass", and the rest is the
// command, which can have more than one line. @HOME@ is the home directory,
// @WORK@ is its parent and @ROOT@ is the parent of @WORK@.
func review6Cases(t *testing.T, home string) (deny, pass []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "review6_cases.txt"))
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Dir(home)
	r := strings.NewReplacer("@HOME@", home, "@WORK@", work, "@ROOT@", filepath.Dir(work))
	for _, block := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n---\n") {
		verdict, cmd, ok := strings.Cut(block, "\n")
		if !ok {
			t.Fatalf("case without a command: %q", block)
		}
		switch verdict {
		case "deny":
			deny = append(deny, r.Replace(cmd))
		case "pass":
			pass = append(pass, r.Replace(cmd))
		default:
			t.Fatalf("case with verdict %q: %q", verdict, block)
		}
	}
	return deny, pass
}

// TestProtectedPathReview6Forms pins every command of the sixth independent
// review. The review ran each one in a real bash. A "deny" command is one the
// check must deny. A "pass" command must stay allowed.
func TestProtectedPathReview6Forms(t *testing.T) {
	home := filepath.Join(t.TempDir(), "work", "h")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.codex/hooks.json", home + "/.tool-guard"}
	deny, pass := review6Cases(t, home)
	if len(deny) < 150 || len(pass) < 35 {
		t.Fatalf("testdata/review6_cases.txt has %d deny and %d pass cases; it was cut", len(deny), len(pass))
	}
	for _, cmd := range deny {
		if hit, _ := shellTouchesProtected(cmd, prefixes); !hit {
			t.Errorf("allowed, want denied: %s", cmd)
		}
	}
	for _, cmd := range pass {
		if hit, target := shellTouchesProtected(cmd, prefixes); hit {
			t.Errorf("denied (%s), want allowed: %s", target, cmd)
		}
	}
}

// TestNameRule pins the rule of protect_mention.go by itself: a command whose
// text names a protected path is denied unless every program is read-only.
func TestNameRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	cases := []struct {
		cmd  string
		want bool
	}{
		// The examples of the example README.
		{"python3 edit.py ~/.claude/settings.json", true},
		{"git checkout ~/.claude/settings.json", true},
		{"cat ~/.claude/settings.json", false},
		{"cd ~/.claude && python3 edit.py settings.json", true},
		// The six ways a path is named.
		{"python3 edit.py $HOME/.claude/settings.json", true},
		{"python3 edit.py ${HOME}/.claude/settings.json", true},
		{"python3 edit.py " + home + "/.claude/settings.json", true},
		{"python3 edit.py '" + home + "'/.claude/\"settings.json\"", true},
		{"python3 edit.py ~/.claude/settin\\gs.json", true},
		{"python3 -c 'open(\"" + home + "/.claude/settings\\x2ejson\",\"w\")'", true},
		{"python3 edit.py $'" + home + "/.claude/settings\\056json'", true},
		{"python3 edit.py $'" + home + "/.claude/settings\\u002ejson'", true},
		{"python3 edit.py ~/.claude/settings.{json,x}", true},
		{"python3 edit.py ~/.claude/set*", true},
		{"python3 edit.py ~/.claude/settings.jso?", true},
		{"python3 edit.py ~/.claude/settings.[j]son", true},
		{"python3 edit.py ~/**/settings.json", true},
		{"python3 edit.py --file=~/.claude/settings.json", true},
		{"python3 edit.py ~/.tool-guard/audit/x", true},
		{"python3 edit.py -o" + home + "/.claude/settings.json", true},
		{"python3 edit.py -vo" + home + "/.claude/settings.json", true},
		{"cd ~/.claude && python3 edit.py -osettings.json", true},
		{"python3 edit.py ~/.claude/settings.jso[n", true}, // a pattern the check cannot read
		{"cat ~/.claude/settings.json <<cat\necho\ncat", true},
		// Constructs the check does not read as bash does.
		{"cat ~/.claude/settings.json # read", true},
		{"cat <<E\n~/.claude/settings.json\nE", true},
		{"cat ${X:-~/.claude/settings.json}", true},
		{"python3 edit.py \"${X:-" + home + "/.claude/settings.json}\"", true},
		{"python3 edit.py x@~/.claude/settings.json", true},
		{"echo $((1)) ~/.claude/settings.json", true},
		{"case x in x) cat ~/.claude/settings.json;; esac", true},
		// Read-only programs.
		{"grep -q hooks ~/.claude/settings.json && echo yes", false},
		{"jq .hooks ~/.claude/settings.json | head -3", false},
		{"bash -c 'cat ~/.claude/settings.json'", false},
		{"/usr/bin/cat ~/.claude/settings.json", false},
		{"echo $(cat ~/.claude/settings.json)", false},
		// An assignment or a wrapper before a read-only program.
		{"x=$(cat ~/.claude/settings.json)", true},
		{"PATH=/tmp/x cat ~/.claude/settings.json", true},
		{"PATH=/tmp/x; cat ~/.claude/settings.json", true},
		{"LD_PRELOAD=/tmp/x.so cat ~/.claude/settings.json", true},
		{"BASH_ENV=/tmp/x bash -c 'cat ~/.claude/settings.json'", true},
		{"env PATH=/tmp/x cat ~/.claude/settings.json", true},
		{"sudo cat ~/.claude/settings.json", true},
		{"! grep -q hooks ~/.claude/settings.json", false},
		{"if test -f ~/.claude/settings.json; then echo yes; fi", false},
		{"ls ~/.claude", false},
		{"bash -c 'python3 edit.py ~/.claude/settings.json'", true},
		{"cat ~/.claude/settings.json | python3 -m json.tool", true},
		{"\"cat\" ~/.claude/settings.json", true}, // a quoted program name is not read as the name
		{"bash fix.sh ~/.claude/settings.json", true},
		{"echo $(python3 edit.py ~/.claude/settings.json)", true},
		{"echo \x60python3 edit.py ~/.claude/settings.json\x60", true},
		{"cd ~/.clau* && python3 edit.py settings.json", true},
		{"f() { cd .claude && python3 edit.py settings.json; }; cd ~ && f", true},
		{"python3 edit.py settings.json; cd .claude; cd ~", true}, // the order of the commands is not followed
		{"~/.claude/settings.json --run", true},
		{"~/.claude/settings.jso? --run", true},
		// The text does not name a protected path: the rule does not apply.
		{"python3 edit.py ~/project/settings.json", false},
		{"python3 edit.py settings.json # note", false},
		{"cd ~/project && python3 edit.py settings.json", false},
		{"mkdir -p out/{1..3}", false},
		{"cp x .", false},
		{"git commit -m 'update .claude/settings.json docs'", false},
	}
	for _, c := range cases {
		if got, _ := shellTouchesProtected(c.cmd, prefixes); got != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestProtectedDirectoryBase: a relative path is read under a directory the
// command names when the directory is a protected path or is inside one and
// the file system has it. A protected file is not such a directory, and a
// read with a pattern and a pipe stays allowed.
func TestProtectedDirectoryBase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range []string{".tool-guard/audit/sub", ".claude"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	cases := []struct {
		cmd  string
		want bool
	}{
		{"cd ~/.tool-guard && echo x > protect-paths", true},
		{"cd ~/.tool-guard/ && echo x > protect-paths", true},
		{"cd ~/.tool-guard/audit && echo x > f", true},
		{"pushd ~/.tool-guard/audit && echo x >> f", true},
		{"cd ~/.tool-guard/audit && cd .. && echo x > protect-paths", true},
		{"cd ~/.tool-guard/audit && cd sub && echo x > ../f", true},
		{"cd ~/.tool-guard/audit && echo x > ../protect-paths", true},
		{"cd ~/.tool-g*/audit && echo x > f", true},
		{"cd ~/.tool-guard/aud?t && echo x > f", true},
		{"ls ~/.tool-guard > list.txt", true},
		{"cd ~/.tool-guard/audit && ls a b c d", false},
		{"cd ~/.tool-g*/audit && ls a b c", false},
		{"cd ~/.tool-guard/missing; echo x > f", false}, // no such directory: cd fails
		{"grep hooks ~/.claude/settings.json > out.txt", false},
		{"cat ~/.claude/*.json | grep hooks | head", false},
		{"ls ~/.claude/*.json | head -3 | wc -l", false},
		{"cat ~/.tool-guard/protect-paths > copy.txt", false},
		// A shell is read through only as "SHELL -c COMMAND".
		{"bash -c 'cat ~/.claude/settings.json'", false},
		{"fish --init-command='python3 edit.py ~/.claude/settings.json' -c true", true},
		{"bash --rcfile x -c 'cat ~/.claude/settings.json'", true},
		{"bash -ic 'cat ~/.claude/settings.json'", true},
		{"cat ~/.claude/settings.json; bash -c -x", true}, // -c with no command
		{"bash -o posix -c 'cat ~/.claude/settings.json'", true},
	}
	for _, c := range cases {
		if got, _ := shellTouchesProtected(c.cmd, prefixes); got != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestNameRuleLimits: a command with more words or more directories than the
// check reads is denied.
func TestNameRuleLimits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json"}
	var words strings.Builder
	words.WriteString("echo")
	for i := 0; i <= maxShellFragments; i++ {
		words.WriteString(" w" + strconv.Itoa(i))
	}
	if hit, _ := shellTouchesProtected(words.String(), prefixes); !hit {
		t.Errorf("a command with more than %d words was allowed", maxShellFragments)
	}
	dirs := "echo"
	dir := "~"
	for i := 0; i <= maxProtectedBases; i++ {
		dir += "/."
		dirs += " " + dir
	}
	if hit, _ := shellTouchesProtected(dirs, prefixes); !hit {
		t.Errorf("a command that names more than %d directories above a protected path was allowed", maxProtectedBases)
	}
	if hit, target := shellTouchesProtected("echo ~ ~/. /tmp", prefixes); hit {
		t.Errorf("a command that names two directories above a protected path was denied (%s)", target)
	}
}

// TestReview6Generate writes testdata/review6_cases.txt from the lists of the
// review when TG_REVIEW6_SRC names their directory. It is a maintenance step.
func TestReview6Generate(t *testing.T) {
	src := os.Getenv("TG_REVIEW6_SRC")
	if src == "" {
		t.Skip("TG_REVIEW6_SRC is not set")
	}
	home := filepath.Join(src, "h")
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.codex/hooks.json", home + "/.tool-guard"}
	r := strings.NewReplacer(home, "@HOME@", src, "@WORK@", filepath.Dir(src), "@ROOT@")
	var out []string
	seen := map[string]bool{}
	for _, name := range []string{"c1.txt", "c2.txt", "c3.txt", "c4.txt", "c5.txt", "b1.txt", "b2.txt"} {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, cmd := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n---\n") {
			if seen[cmd] {
				continue
			}
			seen[cmd] = true
			verdict := "pass"
			if hit, _ := shellTouchesProtected(cmd, prefixes); hit {
				verdict = "deny"
			}
			out = append(out, verdict+"\n"+r.Replace(cmd))
		}
	}
	if err := os.WriteFile(filepath.Join("testdata", "review6_cases.txt"), []byte(strings.Join(out, "\n---\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
