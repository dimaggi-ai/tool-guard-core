package mainfloor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// workdirTree makes ROOT/prot (protected), ROOT/proj/sub, ROOT/free and the
// link ROOT/proj/lnk -> ROOT/prot. It returns ROOT.
func workdirTree(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a symbolic link")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	withCaseProbe(t, false)
	for _, d := range []string{"prot", "proj/sub", "free"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "prot"), filepath.Join(root, "proj", "lnk")); err != nil {
		t.Fatal(err)
	}
	return root
}

func protectHit(t *testing.T, tool, group string, params map[string]interface{}, prefixes []string) bool {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	hit, _ := ViolatesProtectedPaths(&domain.ActionEnvelope{ToolName: tool, ToolGroup: group, Parameters: raw}, prefixes)
	return hit
}

// TestDotDotAfterCdIsReadFromThatDirectory: a relative path with ".." was
// read from the directory of the hook process. After `cd DIR` the shell
// reads it from DIR.
func TestDotDotAfterCdIsReadFromThatDirectory(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"cd " + root + "/proj/sub && echo x > ../../prot/f", true},
		{"pushd " + root + "/proj/sub; cp a ../../prot/f", true},
		{"cd " + root + "/proj/sub && python3 edit.py ../../prot/f", true},
		{"cd " + root + "/proj/sub && echo x > ../../free/f", false},
		{"cd " + root + "/proj/sub && cat ../../prot/f", false},
		{"cd " + root + "/prot/missing; echo x > f", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestWorkDirectoryOfTheCallIsRead: the harness can run a command in a
// directory that is not the directory of the hook process. The directory is
// in the parameters under cwd or workdir.
func TestWorkDirectoryOfTheCallIsRead(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, key := range []string{"cwd", "workdir", "Cwd", "working_directory"} {
		p := map[string]interface{}{"command": "echo x > ../prot/f", key: root + "/proj"}
		if !protectHit(t, "Bash", "", p, prefixes) {
			t.Errorf("command with %s is not denied", key)
		}
		p = map[string]interface{}{"file_path": "../prot/f", "content": "x", key: root + "/proj"}
		if !protectHit(t, "Write", "", p, prefixes) {
			t.Errorf("Write with %s is not denied", key)
		}
		p = map[string]interface{}{"file_path": "/proc/self/cwd/../prot/f", "content": "x", key: root + "/proj"}
		if !protectHit(t, "Write", "", p, prefixes) {
			t.Errorf("Write through /proc/self/cwd with %s is not denied", key)
		}
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "echo x > ../prot/f"}, prefixes) {
		t.Error("the same command with no work directory is denied")
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "echo x > ../free/f", "cwd": root + "/proj"}, prefixes) {
		t.Error("a write to a directory that is not protected is denied")
	}
}

// TestGlobThroughALinkAndFdDirectories: a glob can match a symbolic link to
// a protected directory, and /dev/fd/N/ or /proc/NAME/fd/N/ is a directory
// the check cannot name.
func TestGlobThroughALinkAndFdDirectories(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"echo x > " + root + "/proj/ln?/f", true},
		{"cp a " + root + "/proj/l*/f", true},
		{"echo x > " + root + "/proj/su?/f", false},
		{"cd " + root + "/proj/ln? && echo x > f", true},
		{"cd " + root + "/proj/su? && echo x > f", false},
		{"python3 w.py /proc/$$/root" + root + "/prot/f", true},
		{"python3 w.py /proc/self/task/$$/root" + root + "/prot/f", true},
		{"cat /proc/self/root/etc/hostname", false},
		{"python3 w.py /proc/$$/{cwd,x}/f", true},
		{"python3 w.py /dev/{fd,x}/3/f", true},
		{"echo x > /dev/fd/3/f", true},
		{"echo x > /proc/self/fd/3/f", true},
		{"echo x > /proc/1234/task/7/fd/3/f", true},
		{"echo x >&2", false},
		{"cat /dev/fd/3", false},
		{"echo x > /dev/null", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
	// A pattern is compared with the files that exist, and /proc is there
	// on Linux only.
	if runtime.GOOS == "linux" {
		cmd := "cd " + root + "/prot && echo x > /proc/self/cw?/f"
		if !protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, prefixes) {
			t.Errorf("%q is not denied", cmd)
		}
	}
}

// TestLinkMadeByLnInTheSameCommand: a link that `ln` makes in the command
// does not exist when the hook runs, so a word that goes through it cannot
// be followed. A command that makes a link to a protected path and does
// more than read is denied.
func TestLinkMadeByLnInTheSameCommand(t *testing.T) {
	root := workdirTree(t)
	if err := os.WriteFile(filepath.Join(root, "prot", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{root + "/prot/f"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"ln -s " + root + "/prot " + root + "/free/l && echo x > " + root + "/free/l/f", true},
		{"ln -sfn " + root + "/prot " + root + "/free/l; cp a " + root + "/free/l/f", true},
		{"ln -s " + root + "/prot " + root + "/free/l && python3 edit.py " + root + "/free/l/f", true},
		// A relative target is read under the directory of the link.
		{"ln -s ../prot/f " + root + "/free/s && echo x > " + root + "/free/s", true},
		{"cd " + root + "/free && ln -s ../prot/f s && python3 w.py s", true},
		// cd through the link, and a link to the link.
		{"cd " + root + "/free && ln -s ../prot l && cd l && python3 w.py f", true},
		{"cd " + root + "/free && ln -s ../prot l && ln -s l m && python3 w.py m/f", true},
		{"ln -s -t " + root + "/free " + root + "/prot && python3 w.py " + root + "/free/prot/f", true},
		// The last operand is a directory: the link is made in it, and
		// a relative target is read under it.
		{"ln -s ../../prot/f " + root + "/proj/sub && python3 w.py " + root + "/proj/sub/f", true},
		{"ln -s --target-directory=" + root + "/proj/sub ../../prot/f && python3 w.py " + root + "/proj/sub/f", true},
		{"ln -s ../../../prot/f " + root + "/proj/sub/a/ && python3 w.py x", true},
		{"ln -s ../../free/f " + root + "/proj/sub && python3 w.py " + root + "/proj/sub/f", false},
		// A link to the root directory.
		{"cd " + root + "/free && ln -s / r; python3 w.py r" + root + "/prot/f", true},
		// The ln is in a text that the command runs.
		{"cd " + root + "/free && bash -c 'ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && sh -c 'ln -s ../prot l' && sh -c 'python3 w.py l/f'", true},
		{"cd " + root + "/free && eval ln -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && eval 'ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && echo $(ln -s ../prot l); python3 w.py l/f", true},
		{"cd " + root + "/free && x=$(ln -s ../prot l); python3 w.py l/f", true},
		{"cd " + root + "/free && bash -c 'bash -c \"ln -s ../prot l\"'; echo x > l/f", true},
		{"cd " + root + "/free && bash -c 'ln -s ../prot l' && ls -l", false},
		{"cd " + root + "/free && echo $(ln -s ../prot l); cat l/f", false},
		{"cd " + root + "/free && bash -c 'ln -s ../proj l'; python3 w.py l/f", false},
		// ln under busybox, and ln with operands from xargs.
		{"cd " + root + "/free && busybox ln -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && echo ../prot l | xargs ln -s; python3 w.py l/f", true},
		{"cd " + root + "/free && echo a b | xargs ln -s", false},
		{"cd " + root + "/free && bash -c 'busybox ln -s ../prot l' && ls -l", false},
		// The ln is in a text that a later step can run.
		{"cd " + root + "/free && eval $'ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && eval \"$(echo ln -s ../prot l)\"; python3 w.py l/f", true},
		{"cd " + root + "/free && eval \"$(printf 'ln -s ../prot l')\"; python3 w.py l/f", true},
		{"cd " + root + "/free && c='ln -s ../prot l'; eval \"$c\"; python3 w.py l/f", true},
		{"cd " + root + "/free && echo 'ln -s ../prot l' | bash; python3 w.py l/f", true},
		{"cd " + root + "/free && echo ln -s ../prot l | sh; python3 w.py l/f", true},
		{"cd " + root + "/free && echo -n ln -s ../prot l | sh; python3 w.py l/f", true},
		{"cd " + root + "/free && printf '%s ' ln -s ../prot l | sh; python3 w.py l/f", true},
		{"cd " + root + "/free && printf '%s ' ln -s ../proj l | sh; python3 w.py l/f", false},
		{"cd " + root + "/free && bash <<< 'ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && env -S 'ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && script -qc 'ln -s ../prot l' /dev/null; python3 w.py l/f", true},
		{"cd " + root + "/free && echo 'ln -s ../prot l'", false},
		{"cd " + root + "/free && echo 'ln -s ../proj l' | bash; python3 w.py l/f", false},
		{"cd " + root + "/free && c='ln -s ../proj l'; eval \"$c\"; python3 w.py l/f", false},
		// The ln is after a program that is not read-only.
		{"cd " + root + "/free && flock /tmp/k ln -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && f(){ \"$@\"; }; f ln -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && flock /tmp/k ln -s ../proj l; python3 w.py l/f", false},
		{"cd " + root + "/free && grep ln ../prot l; python3 w.py x", false},
		// A link to the directory of file descriptors or of processes.
		{"cd " + root + "/free && ln -s /dev/fd d; exec 3<" + root + "/prot; python3 w.py d/3/f", true},
		{"cd " + root + "/free && ln -s /proc/self p; python3 w.py p/cwd/f", true},
		{"cd " + root + "/free && ln -s /dev/null d; python3 w.py x", false},
		// A link to a directory that is not protected, and `..` after it.
		{"cd " + root + "/free && ln -s ../proj l; echo x > l/../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py l/../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj/sub l; python3 w.py ./l/../../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; cd l; python3 w.py ../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; cd l/; python3 w.py ../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; cd l/sub; python3 w.py ../../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; pushd l/sub; echo x > ../../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; env -C l/sub sh -c 'echo x > ../../prot/f'", true},
		{"cd " + root + "/free && ln -s ../proj l; (cd l/sub && python3 w.py ../../prot/f)", true},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py ?/../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj $n; python3 w.py k/../prot/f", true},
		{"cd " + root + "/free && bash -c 'ln -s ../proj l'; python3 w.py l/../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; python3 -c \"open('l/../prot/f','w')\"", true},
		{"cd " + root + "/free && ln -s ../proj l; cat l/../prot/f", false},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py l/f", false},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py k/../x", false},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py lx/../x", false},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py x/l", false},
		{"cd " + root + "/free && grep ln l; python3 w.py l/../x", false},
		{"cd " + root + "/free && ln -s ../proj 'my l'; python3 w.py 'my l/../prot/f'", true},
		{"cd " + root + "/free && ln -s ../proj l; ln -s l/.. m; python3 w.py m/prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l; python3 w.py {l,x}/../prot/f", true},
		{"cd " + root + "/free && c=ln; $c -s ../proj l; python3 w.py l/../prot/f", true},
		{"cd " + root + "/free && c=ln; $c -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && $(which ln) -sf ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && c=ln; $c --symbolic ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && c=cp; $c -r ../proj l; python3 w.py l/f", false},
		{"cd " + root + "/free && c=ln; $c -s ../proj l; python3 w.py l/f", false},
		{"cd " + root + "/free && git commit -m 'use ln -s ../a b'; python3 w.py x", false},
		// A text that no step of the command can run does not name the link.
		{"cd " + root + "/free && ln -s ../proj l && git commit -m 'move l/sub up to ../../pkg'", false},
		{"cd " + root + "/free && ln -s ../proj l && git tag -m 'cd l/sub then ../../x' v1", false},
		{"cd " + root + "/free && ln -s ../proj l && git commit -m 'cd l/sub' && python3 w.py ../../prot/f", false},
		{"cd " + root + "/free && ln -s ../proj l && git stash push -m 'l/sub ../../x'", true},
		// A second ln writes through the link, and no other program writes.
		{"cd " + root + "/free && ln -s ../proj l && ln -sf x l/../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l && cd l/sub && ln -sf x ../../prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l && cd l/../prot && ln -sf /tmp/x/f", true},
		{"cd " + root + "/free && ln -s ../proj l && d=l/.. && ln -sf x $d/prot/f", true},
		{"cd " + root + "/free && for a in '../proj l' 'x l/../prot/f'; do ln -sf $a; done", true},
		{"cd " + root + "/free && printf '%s\\n' '../proj l' 'x l/../prot/f' | xargs -L1 ln -sf", true},
		{"cd " + root + "/free && ln -s ../proj l && ln -s l/.. m && ln -sf x m/prot/f", true},
		{"cd " + root + "/free && ln -s ../proj l && cd l/sub && ln -sf x ../../y/f", true},
		{"cd " + root + "/free && bash -c 'ln -s ../proj l && cd l/sub && true" + strings.Repeat(" y", 4200) + " && echo x > ../../y/f'", true},
		{"cd " + root + "/free && f() { ln -sf \"$@\"; }; f ../proj l; f x l/../y/f", true},
		{"cd " + root + "/free && ln -s ../proj l; while :; do ln -sf x l/../y/f; break; done", true},
		{"cd " + root + "/free && ln -s ../a a && ln -s ../b b && ls a b", false},
		{"cd " + root + "/free && ln -sfn releases/5 current && ln -sfn releases/4 previous", false},
		{"cd " + root + "/free && ln -sf ../m/eslint bin/eslint && ln -sf ../m/tsc bin/tsc", false},
		{"cd " + root + "/free && ln -s ../proj l && cd l/sub && ls ../..", false},
		{"cd " + root + "/free && for f in a b; do ln -s x ../etc; done", false},
		// More words than the check reads.
		{"cd " + root + "/free && true" + strings.Repeat(" y", 4200) + " && echo x > a.txt", false},
		{"cd " + root + "/free && true" + strings.Repeat(" y", 4200) + " && ln -s ../proj l && python3 w.py l/a.txt", true},
		{"cd " + root + "/free && true" + strings.Repeat(" y", 4200) + " && bash -c 'ln -s ../proj l && cd l/sub && echo x > ../../prot/f'", true},
		{"cd " + root + "/free && true" + strings.Repeat(" y", 4000) + " && bash -c 'ln -s ../proj l && cd l/sub && echo x > ../../prot/f'", true},
		// The escapes of a $'...' word.
		{"cd " + root + "/free && eval $'ln\\x20-s\\x20../prot\\x20l'; python3 w.py l/f", true},
		{"cd " + root + "/free && eval $'ln\\t-s\\t../prot\\tl'; python3 w.py l/f", true},
		{"cd " + root + "/free && eval $'l\\x6e' -s ../prot l; python3 w.py l/f", true},
		{"cd " + root + "/free && eval $'ln -s ..\\057prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && printf 'ln\\x20-s\\x20../prot\\x20l' | sh; python3 w.py l/f", true},
		{"cd " + root + "/free && eval $'ln\\x20-s\\x20../proj\\x20l'; python3 w.py l/f", false},
		// A command substitution in a parameter expansion.
		{"cd " + root + "/free && : ${x:-$(ln -s ../prot l)}; python3 w.py l/f", true},
		{"cd " + root + "/free && : \"${x:=$(ln -s ../prot l)}\"; python3 w.py l/f", true},
		// A directory that a word before the ln names.
		{"cd " + root + " && env -C proj/sub ln -s ../../prot l; python3 w.py proj/sub/l/f", true},
		{"cd " + root + " && env --chdir=proj/sub ln -s ../../prot l; python3 w.py proj/sub/l/f", true},
		{"cd " + root + " && env -C proj/sub ln -s ../../free l; python3 w.py proj/sub/l/f", false},
		// A text that no step of the command can run.
		{"cd " + root + "/free && echo 'ln -s ../prot l' > note.txt", false},
		{"cd " + root + "/free && git commit -m 'doc: ln -s ../prot l'", false},
		{"cd " + root + "/free && git tag -m 'ln -s ../prot l' v1", false},
		{"cd " + root + "/free && echo 'ln -s ../prot l' | xargs -I@ env -S @; python3 w.py l/f", true},
		{"cd " + root + "/free && echo 'ln -s ../prot l' > r.sh; sh r.sh", true},
		{"cd " + root + "/free && echo 'ln -s ../prot l' > r.sh; . r.sh; python3 w.py l/f", true},
		{"cd " + root + "/free && git -c alias.k='!ln -s ../prot l' k; python3 w.py l/f", true},
		{"cd " + root + "/free && git config alias.k '!ln -s ../prot l'; python3 w.py l/f", true},
		{"cd " + root + "/free && trap 'ln -s ../prot l' EXIT; python3 w.py l/f", true},
		// A word of eval that the check cannot read.
		{"cd " + root + "/free && eval 'ln -s ../prot l'; eval $X", true},
		// More links in a text that the command runs than the check reads.
		{"cd " + root + "/free && bash -c 'ln -s" + strings.Repeat(" a", 70) + " d'; python3 w.py x", true},
		{"cd " + root + "/free && eval ln -s" + strings.Repeat(" a", 70) + " d; python3 w.py x", true},
		// A link to a directory above the protected path. The text does
		// not name the path, so only the link check sees these.
		{"cd " + root + "/free && busybox $L -s " + root + " l; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && busybox $L --symbolic " + root + " l; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && busybox $L " + root + " l; python3 w.py l/prot/f", false},
		{"cd " + root + "/free && echo " + root + "/prot l | xargs ln -s; python3 w.py l/f", true},
		{"cd " + root + "/free && c='ln -s" + strings.Repeat(" a", 70) + " d'; eval \"$c\"; python3 w.py x", true},
		{"cd " + root + "/free && flock /tmp/k ln -s " + root + "/proj l && cd l/sub && echo x > ../../y/f", true},
		{"cd " + root + "/free && grep ln " + root + "/proj l && cd l/sub && echo x > ../../y/f", false},
		// A word of the ln comes from a variable or from a command
		// substitution: the check cannot read the target.
		{"cd " + root + "/free && c=\"ln -s $HOME l\"; eval \"$c\"; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && c=\"ln -s $HOME l\"; $c; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && h=$HOME; c=\"ln -s $h l\"; $c; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && c=\"ln -s $HOME\"; $c l; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && c=ln; $c -s $T l; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && set -- ln -s $T l; \"$@\"; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && c=\"-s $T l\"; eval \"ln $c\"; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && eval \"ln -s $(echo ~) l\"; python3 w.py l/prot/f", true},
		{"cd " + root + "/free && echo \"run ln -s $T l\"", false},
		{"cd " + root + "/free && c=\"git status\"; $c; python3 w.py out.txt", false},
		// The name of the program comes from a variable, and a word is
		// $HOME, a directory above the protected path.
		{"cd " + root + "/free && c=\"ln -s\"; $c $HOME l; python3 w.py l/prot/f", true},
		{"$c \"${HOME}/\" l", true},
		{"$c $HOME/proj l; python3 w.py x", false},
		{"$c $HOME$X l; python3 w.py x", false},
		// The link alone, and the link with a read, are allowed.
		{"ln -s " + root + "/prot " + root + "/free/l", false},
		{"ln -s " + root + "/prot " + root + "/free/l && ls -l " + root + "/free", false},
		{"ln -s " + root + "/proj " + root + "/free/l && echo x > " + root + "/free/l/f", false},
		{"ln -s ../shared " + root + "/free/shared && python3 w.py " + root + "/free/shared/f", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestBraceListWithMoreWordsThanTheCheckMakes: a brace list with more than
// maxBraceWords words is not expanded. It counts as the name of a protected
// path when one of its words can be the path. The shell option nocaseglob
// makes a pattern match without letter case, so a command that holds it
// counts in the same way.
func TestBraceListWithMoreWordsThanTheCheckMakes(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot/f.json"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"python3 w.py " + root + "/prot/f.{json,{1..70}}", true},
		{"python3 w.py " + root + "/prot/{f.json,{1..70}}", true},
		{"python3 w.py " + root + "/{prot,{1..70}}/f.json", true},
		{"python3 w.py --out=" + root + "/prot/f.{json,{1..70}}", true},
		{"python3 w.py ~/prot/f.{json,{1..70}}", true},
		{"python3 w.py $HOME/prot/f.{json,{1..70}}", true},
		{"cd " + root + "/proj && python3 w.py ../prot/f.{json,{1..70}}", true},
		{"cd " + root + " && python3 w.py prot/f.{json,{1..70}}", true},
		{"python3 w.py " + root + "/prot/f.jso{a..z}{,{1..70}}", true},
		{"python3 w.py " + root + "/prot/g.jso{a..z}{,{1..70}}", false},
		{"cat " + root + "/prot/f.{json,{1..70}}", false},
		{"python3 w.py " + root + "/prot/g.{yaml,{1..70}}", false},
		{"python3 w.py " + root + "/free/x{1..70}", false},
		{"cd " + root + " && for i in {1..100}; do curl -s http://x/$i; done", false},
		{"shopt -s nocaseglob; python3 w.py " + root + "/PRO[T]/F.JSO[N]", true},
		{"bash -O nocaseglob -c 'python3 w.py x'", true},
		{"echo nocaseglob", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestCommandSubstitutionIsNotReadOnlyByDefault: a command whose text names
// a protected path is allowed only when every program in it reads, also the
// programs inside $( ).
func TestCommandSubstitutionIsNotReadOnlyByDefault(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"cat " + root + "/prot/f $(python3 w.py)", true},
		{"cat " + root + "/prot/f $(ls)", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestDirectoryAboveAProtectedPathIsABase: a directory that the command
// names is a place a relative path can start from when it is above a
// protected path. This is true also for a pattern that matches no file
// when the hook runs, and for a directory that is read under another
// directory the command names later.
func TestDirectoryAboveAProtectedPathIsABase(t *testing.T) {
	root := workdirTree(t)
	for _, c := range []struct {
		cmd    string
		prefix string
		want   bool
	}{
		{"mkdir -p " + root + "/free/new; cd " + root + "/free/ne? && python3 w.py f", root + "/free/new/f", true},
		{"mkdir -p " + root + "/free/new; cd " + root + "/free/ne? && python3 w.py g", root + "/free/new/f", false},
		{"python3 w.py x -C sub -C " + root + "/proj", root + "/proj/sub/x", true},
		{"python3 w.py y -C sub -C " + root + "/proj", root + "/proj/sub/x", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, []string{c.prefix}); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestLongBraceListIsReadLikeAShortOne: a word with a brace list is read the
// same with 3 words and with 71 words, in each spelling of the word.
func TestLongBraceListIsReadLikeAShortOne(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot/set.json"}
	var long strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&long, "%d,", i)
	}
	for _, c := range []struct {
		word string // L stands for the list of other words
		want bool
	}{
		{root + "/prot/set.{L,json}", true},
		{root + "/pr\"\"ot/set.{L,json}", true},
		{root + "/pr''ot/set.{L,json}", true},
		{root + "/pr\\ot/set.{L,json}", true},
		{"\"" + root + "\"/prot/set.{L,json}", true},
		{root + "/prot/'set'.{L,json}", true},
		{root + "/prot/$'set'.{L,json}", true},
		{root + "/prot/../prot/set.{L,json}", true},
		{root + "/free/../prot/set.{L,json}", true},
		{root + "/pro?/set.{L,json}", true},
		{root + "/pr*/set.{L,json}", true},
		{root + "/prot/s?t.{L,json}", true},
		{root + "/prot/s*.{L,json}", true},
		{root + "/prot/set{L,.json}", true},
		{root + "/{L,prot}/set.json", true},
		{root + "/{L,free/../prot}/set.json", true},
		{root + "/prot/set.{L,{json,g}}", true},
		{root + "/prot/set.{L,json}{,x}", true},
		{root + "/prot/set.{L,{b},json}", true},
		{root + "/prot/set.{L,b{c}d,json}", true},
		{root + "/prot/set.{L,{},json}", true},
		{root + "/prot/set.{L,${X},json}", true},
		{root + "/prot/set.j{L,{b},s}on", true},
		{root + "/prot/a{b/../set.{L,{b},json}", true},
		{root + "/prot/set.j{L,{b},s}{o,{c}}n", true},
		{root + "/{L,prot/set.json}", true},
		{"--out=" + root + "/prot/set.{L,json}", true},
		{root + "/prot/set.{L,jsox}", false},
		{root + "/prot/set.{L,{json}}", false},
		{root + "/prot/sex.{L,json}", false},
		{root + "/free/set.{L,json}", false},
		{root + "/free/../free/set.{L,json}", false},
	} {
		for _, list := range []string{"1,2,", long.String()} {
			word := strings.ReplaceAll(c.word, "L,", list)
			cmd := "python3 w.py " + word
			if got := protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, prefixes); got != c.want {
				t.Errorf("%s with %d other words: hit = %v, want %v", c.word, strings.Count(list, ","), got, c.want)
			}
		}
	}
	// A list of two words, one of them a brace group of one word.
	for cmd, want := range map[string]bool{
		"python3 w.py " + root + "/prot/set.{json,{b}}":  true,
		"python3 w.py " + root + "/prot/set.{{b},json}":  true,
		"python3 w.py " + root + "/prot/set.{json,{}}":   true,
		"python3 w.py " + root + "/prot/set.{jsox,{b}}":  false,
		"python3 w.py " + root + "/prot/set.{json}":      false,
		"python3 w.py " + root + "/prot/se{}t.json":      false,
		"python3 w.py " + root + "/free/${X}/{a}/b.json": false,
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, prefixes); got != want {
			t.Errorf("%s: hit = %v, want %v", cmd, got, want)
		}
	}
	// A number sequence can make a file name of digits.
	digits := []string{root + "/prot/777"}
	if !protectHit(t, "Bash", "", map[string]interface{}{"command": "python3 w.py " + root + "/prot/{1..9}{," + long.String() + "x}"}, digits) {
		t.Error("a number sequence that makes the protected name is not denied")
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "python3 w.py " + root + "/prot/{a..z}{," + long.String() + "x}"}, digits) {
		t.Error("a letter sequence is read as a number")
	}
	// A directory above the protected path, and more words than the check makes.
	for cmd, want := range map[string]bool{
		"rm -r " + root + "/{" + long.String() + "prot}":                                  true,
		"python3 w.py " + root + "/{" + long.String() + "free}":                           false,
		"python3 w.py " + root + "/prot/set.{" + long.String() + "a}{b,c}":                false,
		"python3 w.py " + root + "/prot/{" + long.String() + "a}{" + long.String() + "b}": true,
		"python3 w.py " + root + "/PROT/SET.{" + long.String() + "JSON}":                  true,
		"python3 w.py " + root + "/{" + long.String() + "prot}":                           true,
		"python3 w.py " + root + "/prot/{" + strings.Repeat("a,", 4100) + "b}":            true,
		"python3 w.py " + root + "/free/{1..100000}.txt":                                  false,
		"python3 w.py " + root + "/prot/se{a..z}.{" + long.String() + "json}":             true,
		"python3 w.py " + root + "/prot/se{1..9}.{" + long.String() + "json}":             false,
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, prefixes); got != want {
			t.Errorf("%.60s: hit = %v, want %v", cmd, got, want)
		}
	}
}

// TestNetworkAddressIsNotAPath: the host and path of a network address are
// not a path on this machine. A file:// address is.
func TestNetworkAddressIsNotAPath(t *testing.T) {
	prefixes := []string{"/srv9/data"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"git clone https://srv9/data", false},
		{"curl -o out --url=http://srv9/data/x", false},
		{"git push file:///srv9/data", true},
		{"python3 w.py x:/srv9/data/f", true},
		{"python3 w.py --out=/srv9/data/f,http://h/x", true},
		{"python3 w.py https://h/x //srv9/data/f", true},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestDirectoryNamedByAnOptionIsABaseForDotDot: a directory that the
// command names without cd (tar -C DIR, git -C DIR) is a place a relative
// path with ".." can start from.
func TestDirectoryNamedByAnOptionIsABaseForDotDot(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"tar -C " + root + "/proj/sub -xf a.tar ../../prot/f", true},
		{"tar -C " + root + "/proj/sub -xf a.tar ../../free/f", false},
	} {
		if got := protectHit(t, "Bash", "", map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("%q: hit = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestUnknownToolCommandCountsOnlyWhenItNamesAProtectedPath: the command of
// a tool that is not a known shell can be SQL or JavaScript. It is denied
// only when the text names a protected path.
func TestUnknownToolCommandCountsOnlyWhenItNamesAProtectedPath(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}
	for _, c := range []struct {
		tool, group, cmd string
		want             bool
	}{
		{"mcp__pg__query", "shell", "SELECT * FROM t WHERE a > $1", false},
		{"mcp__x__y", "shell", "x=$(1)", false},
		{"FooBar", "shell", "deploy > $ENV", false},
		{"FooBar", "shell", "echo x > " + root + "/prot/f", true},
		{"mcp__sh__run", "shell", "echo x > ~/prot/f", true},
		{"Glob", "shell", "echo x > " + root + "/prot/f", false},
		{"exec_command", "shell", "echo x > " + root + "/prot/f", true},
		{"shell_command", "", "echo x > " + root + "/prot/f", true},
		{"local_shell", "", "echo x > " + root + "/prot/f", true},
	} {
		if got := protectHit(t, c.tool, c.group, map[string]interface{}{"command": c.cmd}, prefixes); got != c.want {
			t.Errorf("tool %q, %q: hit = %v, want %v", c.tool, c.cmd, got, c.want)
		}
	}
}

// TestProtectedPathCheckHasATimeLimit: a check that does not end in the
// time limit denies the call, and long inputs end in the limit.
func TestProtectedPathCheckHasATimeLimit(t *testing.T) {
	root := workdirTree(t)
	prefixes := []string{root + "/prot"}

	// Long inputs. Without the cap on paired operands the cp command took
	// 4.2 s on Linux, and 8.9 s with the race detector on, so its fixed
	// limit finds the removal of that cap. The long path took 0.07 s on
	// Linux, and 1.1 s with the race detector on, with and without its
	// cap. A fixed 4 s limit on it failed on a macOS runner (4.08 s). Its
	// limit is protectBudget, the time after which the caller gets a deny.
	var cp strings.Builder
	cp.WriteString("cp")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&cp, " %sw%d", strings.Repeat("../", 30), i)
	}
	long := root + "/proj/lnk" + strings.Repeat("/../proj/lnk", 3000) + "/x"
	for _, c := range []struct {
		name, tool string
		params     map[string]interface{}
		limit      time.Duration
	}{
		{"cp with 200 operands", "Bash", map[string]interface{}{"command": cp.String()}, 4 * time.Second},
		{"write of a 36 KB path", "Write", map[string]interface{}{"file_path": long, "content": "x"}, protectBudget},
	} {
		start := time.Now()
		protectHit(t, c.tool, "", c.params, prefixes)
		if d := time.Since(start); d >= c.limit {
			t.Errorf("%s took %s, the limit is %s", c.name, d, c.limit)
		}
	}
	// The destination of a long operand list is still read.
	var many strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&many, " a%d", i)
	}
	for _, cmd := range []string{
		"cp" + many.String() + " " + root + "/prot",
		"cp -t " + root + "/prot" + many.String(),
		"cp --target-directory=" + root + "/prot" + many.String(),
	} {
		if !protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, prefixes) {
			t.Errorf("%.40s ...: not denied", cmd)
		}
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "cp" + many.String() + " " + root + "/free"}, prefixes) {
		t.Error("cp of 40 files to a directory that is not protected is denied")
	}
	keep := []string{root + "/free/keep.txt"}
	for _, cmd := range []string{
		"cp" + many.String() + " keep.txt " + root + "/free",
		"cp -t " + root + "/free" + many.String() + " keep.txt",
		"cp --target-directory=" + root + "/free" + many.String() + " keep.txt",
	} {
		if !protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, keep) {
			t.Errorf("%.50s ...: not denied", cmd)
		}
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "cp" + many.String() + " other.txt " + root + "/free"}, keep) {
		t.Error("cp of a file with another name is denied")
	}
	// A copied directory that lands above the protected path. Only the
	// join of the destination with the name of a source finds it.
	deep := []string{root + "/free/d/keep.txt"}
	for _, cmd := range []string{
		"cp -r" + many.String() + " x/d " + root + "/free",
		"cp -r" + many.String() + " -t " + root + "/free x/d",
		"cp -r --target-directory=" + root + "/free" + many.String() + " x/d",
	} {
		if !protectHit(t, "Bash", "", map[string]interface{}{"command": cmd}, deep) {
			t.Errorf("%.50s ...: not denied", cmd)
		}
	}
	if protectHit(t, "Bash", "", map[string]interface{}{"command": "cp -r" + many.String() + " x/e " + root + "/free"}, deep) {
		t.Error("cp of a directory with another name is denied")
	}

	// A check that is too slow is a denial.
	old := protectBudget
	protectBudget = time.Nanosecond
	defer func() { protectBudget = old }()
	var slow strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&slow, "cd /tmp/d%d ; ", i)
	}
	slow.WriteString("cp a")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&slow, " %sw%d", strings.Repeat("../", 30), i)
	}
	raw, _ := json.Marshal(map[string]string{"command": slow.String()})
	hit, why := ViolatesProtectedPaths(&domain.ActionEnvelope{ToolName: "Bash", Parameters: raw}, prefixes)
	if !hit || !strings.Contains(why, "did not end in") {
		t.Errorf("slow check: hit = %v, reason %q", hit, why)
	}
}
