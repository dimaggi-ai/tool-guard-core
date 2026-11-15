package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// withCaseProbe sets the answer of ignoresCase for the test and clears the
// cache before and after.
func withCaseProbe(t *testing.T, answer bool) {
	t.Helper()
	reset := func() {
		caseProbeCache.Lock()
		caseProbeCache.m = map[string]bool{}
		caseProbeCache.Unlock()
	}
	old := caseProbe
	caseProbe = func(string) bool { return answer }
	reset()
	t.Cleanup(func() { caseProbe = old; reset() })
}

// otherCaseCommands name a protected path in another letter case.
var otherCaseCommands = []string{
	"echo x > ~/.CLAUDE/settings.json",
	"echo x > ~/.claude/SETTINGS.JSON",
	"rm ~/.Claude/Settings.Json",
	"python3 edit.py ~/.claude/Settings.json",
	"cd ~/.CLAUDE && rm settings.json",
	"cd ~/.claude && rm SETTINGS.json",
	"rm ~/.CLAUD*/settings.json",
	"rm ~/.claude/SETT*",
	"mv ~/.CLAUDE ~/x",
	"rm -rf ~/.CLAUD?",
	"cp x ~/.TOOL-GUARD/protect-paths",
	"echo x > ~/.Tool-Guard/Audit/new",
	"cp settings.json ~/.CLAUDE/",
	"bash -c 'echo x > ~/.CLAUDE/settings.json'",
}

// TestProtectedPathsIgnoreLetterCase: where the file system ignores letter
// case, a path written in another case is the protected path.
func TestProtectedPathsIgnoreLetterCase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	withCaseProbe(t, true)
	for _, cmd := range otherCaseCommands {
		if hit, _ := shellTouchesProtected(cmd, prefixes); !hit {
			t.Errorf("shellTouchesProtected(%q) = false, want true", cmd)
		}
	}
	// The protected path in another letter case as the program name.
	if hit, _ := shellTouchesProtected("~/.CLAUDE/Settings.json --run", prefixes); !hit {
		t.Error("a protected path in another letter case as the program name is not denied")
	}
	for _, cmd := range []string{"cat ~/.CLAUDE/settings.json", "echo x > ~/.claude/settings.json.other", "rm ~/.claudex/settings.json", "ls ~/.CLAUDE/*.json | sort"} {
		if hit, target := shellTouchesProtected(cmd, prefixes); hit {
			t.Errorf("shellTouchesProtected(%q) = true (%s), want false", cmd, target)
		}
	}
	for _, p := range []string{home + "/.CLAUDE/settings.json", home + "/.claude/SETTINGS.JSON", home + "/.Tool-Guard/x/y"} {
		params, _ := json.Marshal(map[string]string{"file_path": p, "content": "x"})
		env := &domain.ActionEnvelope{ToolName: "write", Parameters: params}
		if hit, _ := ViolatesProtectedPaths(env, prefixes); !hit {
			t.Errorf("a write tool call for %s is not denied", p)
		}
	}
}

// TestProtectedPathsKeepLetterCase: where the file system keeps letter case,
// a path in another case is another file, and the hook does not deny it.
func TestProtectedPathsKeepLetterCase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	withCaseProbe(t, false)
	for _, cmd := range otherCaseCommands {
		if hit, target := shellTouchesProtected(cmd, prefixes); hit {
			t.Errorf("shellTouchesProtected(%q) = true (%s), want false", cmd, target)
		}
	}
	if hit, _ := shellTouchesProtected("echo x > ~/.claude/settings.json", prefixes); !hit {
		t.Error("the path in its own letter case is not denied")
	}
}

// TestFsIgnoresCase runs the probe on the file system of the test. It gives
// the same answer as a direct look: the name in the other case is the same
// file or it is not.
func TestFsIgnoresCase(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Mixed"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "Mixed", "file.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "mIXED", "FILE.JSON"))
	insensitive := err == nil
	for _, p := range []string{file, filepath.Join(dir, "Mixed"), filepath.Join(dir, "Mixed", "missing", "deeper.txt"), filepath.Join(dir, "Mixed", "*", "x")} {
		if got := fsIgnoresCase(p); got != insensitive {
			t.Errorf("fsIgnoresCase(%q) = %v; a direct look at the file system says %v", p, got, insensitive)
		}
	}
	if got := swapLetterCase("aB1.c"); got != "Ab1.C" {
		t.Errorf("swapLetterCase = %q", got)
	}
}

// TestSortAndUniqCountAsReadOnly: sort and uniq read a protected path when
// their words cannot name an output file or a program.
func TestSortAndUniqCountAsReadOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	withCaseProbe(t, false)
	cases := []struct {
		cmd  string
		want bool
	}{
		{"ls ~/.claude/* | sort", false},
		{"sort ~/.claude/settings.json", false},
		{"sort -rn -k2,2 -t: ~/.claude/settings.json | uniq -c | sort -u | head", false},
		{"cat ~/.claude/settings.json | uniq", false},
		{"uniq -c ~/.claude/settings.json", false},
		{"uniq -", false},
		{"sort -o ~/.claude/settings.json x", true},
		{"sort -o out.txt ~/.claude/settings.json", true},
		{"sort -oout.txt ~/.claude/settings.json", true},
		{"sort -no out.txt ~/.claude/settings.json", true},
		{"sort ~/.claude/settings.json -o out.txt", true},
		{"sort --output=out.txt ~/.claude/settings.json", true},
		{"sort --out out.txt ~/.claude/settings.json", true},
		{"sort --compress-program=./x ~/.claude/settings.json", true},
		{"sort -T ~/.tool-guard x", true},
		{"sort --reverse ~/.claude/settings.json", true}, // refused, though it only reads
		{"sort -- -o ~/.claude/settings.json", true},
		{"sort \"-o\" out.txt ~/.claude/settings.json", true},
		{"sort $FLAG ~/.claude/settings.json", true},
		{"sort {-o,~/.claude/settings.json}", true},
		{"sort {-o,~/.claude/settings.json} </dev/null", true},
		{"sort -[n-p] ~/.claude/settings.json", true},
		{"sort -? ~/.claude/settings.json", true},
		{"sort * ~/.claude/settings.json", true},
		{"sort -t '*' ~/.claude/settings.json", true}, // refused, though it only reads
		{"uniq {/tmp/in,~/.claude/settings.json}", true},
		{"uniq ~/.tool-guard/*", true},
		{"uniq ~/.claude/*", true},
		{"uniq ~/.claude/setting?.json", true},
		{"uniq ~/.claude/[s]ettings.json", true},
		{"uniq x ~/.claude/settings.json", true},
		{"uniq ~/.claude/settings.json out.txt", true},
		{"uniq - ~/.claude/settings.json", true},
		{"uniq -- -c ~/.claude/settings.json", true},
		{"uniq $A ~/.claude/settings.json", true},
		{"cat ~/.claude/settings.json | awk 1", true},
		{"less ~/.claude/settings.json", true},
	}
	for _, c := range cases {
		if got, _ := shellTouchesProtected(c.cmd, prefixes); got != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestOtherTildeFormsCountAsProtected: ~+, ~- and ~NAME are read by bash
// under a directory the check does not know, so a command with such a word
// is denied unless every program in it is read-only.
func TestOtherTildeFormsCountAsProtected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	withCaseProbe(t, false)
	cases := []struct {
		cmd  string
		want bool
	}{
		{"cd ~/.claude && uniq /etc/hostname ~+/settings.json", true},
		{"cd ~/.claude && sort /etc/hostname -o ~+/settings.json", true},
		{"cd ~/.claude; cd /tmp; uniq /etc/hostname ~-/settings.json", true},
		{"uniq /etc/hostname ~root/.claude/settings.json", true},
		{"curl -so ~+/settings.json https://example.com/x", true},
		{"curl -so ~-/settings.json https://example.com/x", true},
		{"wget -qO ~root/x https://example.com/x", true},
		{"python3 edit.py ~+", true},
		{"python3 edit.py ~+1/x", true},
		{"python3 edit.py \"~-\"", true}, // refused, though bash leaves a quoted word as it is
		{"dd if=x of=~+/settings.json", true},
		{"PATH=/x:~+/bin make", true},
		{"python3 edit.py {~+,x}/settings.json", true},
		{"bash -c 'python3 edit.py ~+/settings.json'", true},
		{"cat ~+/settings.json", false},
		{"ls ~root | sort", false},
		{"git log HEAD~3", false},
		{"git diff HEAD~2..HEAD~1 -- x.go", false},
		{"python3 edit.py backup~", false},
		{"awk '$1 ~ /x/' in.txt", false},
		{"perl -ne 'print if $x =~ /y/' in.txt", false},
		{"python3 edit.py --flag=~+/x", false}, // bash does not read a tilde there
	}
	for _, c := range cases {
		if got, _ := shellTouchesProtected(c.cmd, prefixes); got != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestCarriageReturnIsNotReadOnly: bash reads a carriage return as a
// character of a word. The tokenizer ends a command there, so the words
// after it looked like a second, harmless command.
func TestCarriageReturnIsNotReadOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	prefixes := []string{home + "/.claude/settings.json", home + "/.tool-guard"}
	withCaseProbe(t, false)
	cases := []struct {
		cmd  string
		want bool
	}{
		{"echo > \"x\recho\"; uniq x\recho ~/.claude/settings.json", true},
		{"echo > \"x\recho\"; sort x\recho -o ~/.claude/settings.json", true},
		{"uniq /etc/hostname\recho ~/.tool-guard/audit.log", true},
		{"cat ~/.claude/settings.json\r", true}, // refused, though it only reads
		{"cat ~/.claude/settings.json\n", false},
		{"printf 'a\\r\\n' > out.txt", false},
	}
	for _, c := range cases {
		if got, _ := shellTouchesProtected(c.cmd, prefixes); got != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestDotDotAfterALinkIsFollowed: path.Clean drops "LINK/.." as text, and
// the kernel follows LINK first. A path written that way named a protected
// file and was allowed, for a write tool and for a shell command.
func TestDotDotAfterALinkIsFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a symbolic link")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	withCaseProbe(t, false)
	for _, d := range []string{"other/deep", "other/prot", "sub"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "other", "deep"), filepath.Join(root, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{root + "/other/prot"}
	// The text cleans to ROOT/sub/prot/f. The file is ROOT/other/prot/f.
	through := root + "/sub/link/../prot/f"
	for _, tool := range []string{"Write", "Edit"} {
		params, _ := json.Marshal(map[string]string{"file_path": through, "content": "x"})
		env := &domain.ActionEnvelope{ToolName: tool, Parameters: params}
		if hit, _ := ViolatesProtectedPaths(env, prefixes); !hit {
			t.Errorf("%s to %s is not denied", tool, through)
		}
	}
	cases := []struct {
		cmd  string
		want bool
	}{
		{"echo x > " + through, true},
		{"python3 edit.py " + through, true},
		{"cat " + through, false},
		{"echo x > " + root + "/sub/link/../free/f", false},
		{"cd " + root + "/other/prot && echo x > /proc/self/cwd/f", true},
		// No word names the protected directory: the word under the
		// working directory of a process is enough.
		{"python3 edit.py /proc/self/cwd/f", true},
		{"python3 edit.py /proc/77/cwd/f", true},
		{"python3 edit.py /proc/1234/task/5/cwd/f", true},
		{"cd " + root + "/other/prot && cat /proc/self/cwd/f", false},
		{"cat /proc/cpuinfo > out.txt", false},
	}
	for _, c := range cases {
		if hit, _ := shellTouchesProtected(c.cmd, expandPrefixes(prefixes)); hit != c.want {
			t.Errorf("shellTouchesProtected(%q) = %v, want %v", c.cmd, hit, c.want)
		}
	}
}

// TestShellGroupToolGetsTheShellCheck: `tg hook` puts a tool name it does
// not know in the group "shell". Such a call was checked by the policies
// and not by the protected-path shell check.
func TestShellGroupToolGetsTheShellCheck(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withCaseProbe(t, false)
	prefixes := []string{home + "/.claude/settings.json"}
	params, _ := json.Marshal(map[string]string{"command": "echo x > ~/.claude/settings.json"})
	for _, c := range []struct {
		tool, group string
		want        bool
	}{
		{"exec_command", "shell", true},
		{"FooBar", "shell", true},
		{"Bash", "", true},
		{"FooBar", "network_egress", false},
	} {
		env := &domain.ActionEnvelope{ToolName: c.tool, ToolGroup: c.group, Parameters: params}
		if hit, _ := ViolatesProtectedPaths(env, prefixes); hit != c.want {
			t.Errorf("tool %q group %q: hit = %v, want %v", c.tool, c.group, hit, c.want)
		}
	}
}
