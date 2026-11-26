package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestReview090ShellRunOptionShape varies the option of the shell call: the
// denial must follow the option that makes the shell run commands, not the
// path text, which is the same in every case.
func TestReview090ShellRunOptionShape(t *testing.T) {
	file := "/tmp/x/.claude/settings.json"
	prefixes := []string{file}
	cases := []struct {
		cmd  string
		want bool
		why  string
	}{
		{"bash -c -i 'cat " + file + "'", true, "-i between the -c and the text"},
		{"bash -c -s 'cat " + file + "'", true, "-s between the -c and the text"},
		{"bash -ic 'cat " + file + "'", true, "cluster carries c and i"},
		{"zsh -c -i 'cat " + file + "'", true, "zsh same shape"},
		{"bash -c 'cat " + file + "' -i", false, "-i after the text: arguments only"},
		{"bash -c 'cat " + file + "'", false, "-c is the first option"},
		{"bash -c -e 'cat " + file + "'", false, "-e changes behaviour only"},
		{"bash -c -x 'cat " + file + "'", false, "-x changes behaviour only"},
		{"cat " + file, false, "not a shell"},
	}
	for _, c := range cases {
		if got := shellCommandRunOptionNamesProtected(c.cmd, prefixes, nil); got != c.want {
			t.Errorf("%s (%s): got %v want %v", c.cmd, c.why, got, c.want)
		}
	}
	if shellCommandRunOptionNamesProtected("bash -c -i 'cat "+file+"'", prefixes, nil) ==
		shellCommandRunOptionNamesProtected("bash -c -e 'cat "+file+"'", prefixes, nil) {
		t.Errorf("the answer does not depend on the option")
	}
	if hit, _ := shellTouchesProtectedRec("bash -c -i 'cat "+file+"'", prefixes, 0, nil, nil); !hit {
		t.Errorf("whole command bash -c -i 'cat F' not denied")
	}
	if hit, _ := shellTouchesProtectedRec("bash -c 'cat "+file+"'", prefixes, 0, nil, nil); hit {
		t.Errorf("whole command bash -c 'cat F' denied, want allowed")
	}
}

// TestReview090LongBraceCost measures the long brace-list rule with the
// number of words in the list as the variable, and counts the file-system
// lookups the rule makes for the whole series. The denial of the word is
// checked through the same entry the hook uses.
func TestReview090LongBraceCost(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	cdir := filepath.Join(home, ".claude")
	// lnk leads to .claude/sub, so lnk/.. is .claude and the word names the
	// protected file.
	if err := os.MkdirAll(filepath.Join(cdir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cdir, "sub"), filepath.Join(home, "lnk")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cdir, "settings.json")
	prefixes := []string{filepath.ToSlash(file)}
	saved, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(home); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(saved); err != nil {
			t.Fatal(err)
		}
	}()
	look0 := procSyscalls()
	for _, n := range []int{10, 70, 200, 500} {
		word := "lnk/../settings.{json,{1.." + itoa(n) + "}}"
		cmd := "python3 w.py " + word
		start := time.Now()
		hit, _ := shellTouchesProtectedRec(cmd, prefixes, 0, nil, []string{filepath.ToSlash(home)})
		t.Logf("COST n=%d %s", n, time.Since(start).Round(time.Microsecond))
		if !hit {
			t.Errorf("n=%d: long list after a link into the protected directory allowed", n)
		}
	}
	// The same word over a plain directory (no link) stays allowed, so the
	// denial above comes from the link and not from the size of the list.
	free := filepath.Join(home, "free")
	if err := os.MkdirAll(free, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{10, 500} {
		word := "free/../free/set.{json,{1.." + itoa(n) + "}}"
		cmd := "cat " + word
		if got := commandNamesProtected(tokenizeShell(cmd), []string{word}, []string{filepath.ToSlash(home)}, nil, nil, prefixes); got != "" {
			t.Errorf("n=%d: plain dir/../dir long list denied: %s", n, got)
		}
	}
	t.Logf("COST statLookups=%d", procSyscalls()-look0)
	if got := procSyscalls() - look0; got > 200 {
		t.Errorf("the long brace list asked the disk %d times", got)
	}
}

func procSyscalls() int {
	b, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "syscr:" {
			v, _ := strconv.Atoi(f[1])
			return v
		}
	}
	return -1
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}

func fields(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestReview090ShellRunOptionAtTheEnd covers the option after the text of
// the -c, where bash takes the -c as its last option: only an option that
// makes the shell run commands is denied there, and a read of a protected
// path stays allowed. The option letter is the variable.
func TestReview090ShellRunOptionAtTheEnd(t *testing.T) {
	file := "/tmp/x/.claude/settings.json"
	prefixes := []string{file}
	for _, c := range []struct {
		cmd  string
		want bool
		why  string
	}{
		{"bash -c 'cat " + file + "' -i", false, "bash has no -i after the -c: an argument"},
		{"bash -c 'cat " + file + "' -s", false, "bash takes no option after the -c: -s is an argument"},
		{"bash -x -c 'cat " + file + "'", false, "-x only changes how the shell behaves"},
		{"bash -e -c 'cat " + file + "'", false, "-e only changes how the shell behaves"},
		{"fish -c 'cat " + file + "' --init-command 'cat " + file + "'", false, "the fish option only reads, and the hook test keeps it allowed"},
		{"bash -c -e 'cat " + file + "'", false, "-e changes behaviour only"},
		{"bash -c -x 'cat " + file + "'", false, "-x changes behaviour only"},
		{"bash -c -i 'cat " + file + "'", true, "-i stands before the text"},
	} {
		got := shellCommandRunOptionNamesProtected(c.cmd, prefixes, nil)
		args := shellDashCArgs(stripCommandPrefix(commandWords(splitShellSegments(tokenizeShell(c.cmd))[0]))[1:])
		if got != c.want {
			t.Errorf("%s: got %v want %v (dashCArgs=%d)", c.cmd, got, c.want, len(args))
		}
	}
}
