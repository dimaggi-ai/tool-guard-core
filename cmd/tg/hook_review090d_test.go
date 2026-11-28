package main

// Fourth-round regression tests for PR #93: the bypasses and regressions
// the review panel found in round 3 (2026-11-26), and the false positives
// they named. Every case runs through the hook with the shipped policy, as
// a subtest of its own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// review090dTree extends review090cTree with links to /dev/fd/3 and
// /proc/self/fd/3 and with 70 plain directories.
func review090dTree(t *testing.T) (home, cdir, file string, dirs []string) {
	t.Helper()
	home, cdir, file = review090cTree(t)
	for name, target := range map[string]string{"pl3": "/dev/fd/3", "plp3": "/proc/self/fd/3"} {
		if err := os.Symlink(target, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 70; i++ {
		d := filepath.Join(home, "dd"+itoa(i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, d)
	}
	return home, cdir, file, dirs
}

// review090dRun runs the hook with an absolute policy path, so a test can
// change the working directory of the process first.
func review090dRun(t *testing.T, ev map[string]interface{}, file string) (string, string) {
	t.Helper()
	pol, err := filepath.Abs(review090bShellPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return review090bRun(t, ev, pol, "-protect-path", file)
}

func TestReview090dProtectedPathBypasses(t *testing.T) {
	home, cdir, file, dirs := review090dTree(t)
	L := "{json,{1..70}}"
	x := "echo x > $X"
	write := func(cwd, fp string) map[string]interface{} {
		return toolEv("Write", cwd, map[string]interface{}{"file_path": fp, "content": "x"})
	}
	patch := review090cPatch("settings.json")
	deep := map[string]interface{}{"patch": review090cPatch(file)}
	for i := 0; i < 17; i++ {
		deep = map[string]interface{}{"a": deep}
	}
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// Fable 2 and 3: a quote, an escaped brace or a quoted brace inside
		// a long brace list.
		{"long list with \\\" in quotes", bashEv(`python3 w.py {"a\"b",.{claude,{1..70}}/settings.json}`, home)},
		{"long list with balanced quotes", bashEv(`python3 w.py {"\"'",.{cl\aude,{1..70}}/settings.json,"'",\"}`, home)},
		{"long list with \\{", bashEv(`python3 w.py {\{,.{claude,{1..70}}/settings.json}`, home)},
		{"long list with x\\}", bashEv(`python3 w.py {x\},.{claude,{1..70}}/settings.json}`, home)},
		{"long list with \\{ and a link", bashEv(`python3 w.py {\{,dlink/settings.`+L+`}`, home)},
		{"long list with \"{\"", bashEv(`python3 w.py {"{",.claude/settings.`+L+`}`, home)},
		{"long list with '}'", bashEv(`python3 w.py {'}',.claude/settings.`+L+`}`, home)},
		{"long list with \\,", bashEv(`python3 w.py {\,,.claude/settings.`+L+`}`, home)},
		{"short list with \\{", bashEv(`python3 w.py {\{,.claude/settings.json}`, home)},
		// Fable 4: more directories than the walker reads.
		{"70 directories then cd lnk ..", bashEv("ls "+strings.Join(dirs, " ")+"; env -C lnk python3 w.py ../settings."+L, home)},
		// Fable 5: a command text in quotes or with escaped separators.
		{"eval \"...long list\"", bashEv(`eval "python3 w.py .{claude,{1..70}}/settings.json"`, home)},
		{"eval '...long list'", bashEv(`eval 'python3 w.py .claude/settings.`+L+`'`, home)},
		{"eval with escaped space", bashEv(`eval python3 w.py\ .{claude,{1..70}}/settings.json`, home)},
		{"trap '...long list'", bashEv(`trap 'python3 w.py .claude/settings.`+L+`' EXIT`, home)},
		{"alias with a long list", bashEv(`alias z='python3 w.py .claude/settings.`+L+`'; z`, home)},
		{"eval x\\;long list", bashEv(`eval x\;.claude/settings.`+L, home)},
		{"eval x\\|long list", bashEv(`eval x\|.claude/settings.`+L, home)},
		// Fable 6: an unread directory, then "..".
		{"cd $D then ../long list", bashEv("D=lnk; cd $D; python3 w.py ../settings."+L, home)},
		{"env -C $D then ../long list", bashEv("D=lnk; env -C $D python3 w.py ../settings."+L, home)},
		{"env -C\"$D\" then ../long list", bashEv(`D=lnk; env -C"$D" python3 w.py ../settings.`+L, home)},
		// Fable 7: zsh --emulate takes a value; an unknown long option.
		{"zsh --emulate sh -c", bashEv("zsh --emulate sh -c '"+x+"'", home)},
		{"bash --unknownopt -c", bashEv("bash --unknownopt -c '"+x+"'", home)},
		{"bash --unknownopt val -c", bashEv("bash --unknownopt val -c '"+x+"'", home)},
		// Fable 8 and Gemini 4: a glued -C and a -C under ~.
		{"env -Clnk sh -c '> ../settings.json'", bashEv("env -Clnk sh -c 'echo x > ../settings.json'", home)},
		{"env -Clnk ../long list", bashEv("env -Clnk python3 w.py ../settings."+L, home)},
		{"tar -Clnk -cf ../long list", bashEv("tar -Clnk -cf ../settings."+L+" /etc/hosts", home)},
		{"env -C ~/lnk ../settings.json", bashEv("env -C ~/lnk python3 w.py ../settings.json", "/tmp")},
		{"env -C ~/lnk ../long list", bashEv("env -C ~/lnk python3 w.py ../settings."+L, "/tmp")},
		// Fable 9: an extglob pattern.
		{"extglob with a long list", bashEv("python3 w.py .claude/@(settings)."+L, home)},
		{"extglob", bashEv("python3 w.py .claude/@(settings).json", home)},
		// Gemini 1: fish with a glued value that holds a variable.
		{"fish -C\"...$X\" -c", bashEv(`fish -C"sh -c 'echo x > $X'" -c true`, home)},
		{"fish -iC\"...$X\" -c", bashEv(`fish -iC"sh -c 'echo x > $X'" -c true`, home)},
		{"fish -c\"...$X\"", bashEv(`fish -c"sh -c 'echo x > $X'"`, home)},
		// Gemini 2: a relative link into /proc or /dev/fd.
		{"Write pl/settings.json", write(home, "pl/settings.json")},
		{"Write pl3/settings.json", write(home, "pl3/settings.json")},
		{"Write plp3/settings.json", write(home, "plp3/settings.json")},
		{"redirect pl3/settings.json", bashEv("echo x > pl3/settings.json", home)},
		{"cd .claude then ../pl", bashEv("cd .claude && echo x > ../pl/settings.json", home)},
		{"Write pl/settings.json, no cwd", noCwd(write(home, "pl/settings.json"))},
		{"Write pl3/settings.json, no cwd", noCwd(write(home, "pl3/settings.json"))},
		{"Write plp3/settings.json, no cwd", noCwd(write(home, "plp3/settings.json"))},
		{"redirect pl3/settings.json, no cwd", noCwd(bashEv("echo x > pl3/settings.json", home))},
		{"cd .claude then ../pl, no cwd", noCwd(bashEv("cd .claude && echo x > ../pl/settings.json", home))},
		// Gemini 3: the files fish writes.
		{"cd .claude then fish -No", bashEv("cd .claude && fish -Nosettings.json -c true", home)},
		{"fish -No under .claude", bashEv("fish -Nosettings.json -c true", cdir)},
		{"fish -Nolnk/..", bashEv("fish -Nolnk/../settings.json -c true", home)},
		{"fish -o .claude/settings.json", bashEv("fish -o .claude/settings.json -c true", home)},
		{"fish --debug-output=", bashEv("fish --debug-output=.claude/settings.json -c true", home)},
		{"fish --profile short list", bashEv("fish --profile .claude/settings.{json,a} -c true", home)},
		// Gemini 5: a short list after a glued option or a quote.
		{"tar -cvvvvvvvf short list", bashEv("tar -cvvvvvvvfsettings.{json,a} /etc/hosts", cdir)},
		{"a+ then a short list", bashEv("python3 w.py a+.claude/settings.{json,{1..5}}", home)},
		{"\"x\" then a short list", bashEv(`python3 w.py "x".claude/settings.{json,{1..5}}`, home)},
		// Gemini 6: a stream that is a file opened for input.
		{"exec 1< P then /dev/stdout", bashEv("exec 1< "+file+"; echo x > /dev/stdout", home)},
		{"1<> P then /dev/stdout", bashEv("echo x 1<>"+file+" > /dev/stdout", home)},
		{"2< P then /dev/stderr", bashEv("cat 2< "+file+" 2>/dev/stderr", home)},
		{"exec 1>&0 then /dev/stdout", bashEv("exec <$X; exec 1>&0; echo x > /dev/stdout", home)},
		// Gemini 8: apply_patch with a nested work directory, other keys,
		// and a patch nested too deep to read.
		{"apply_patch input.workdir", toolEv("apply_patch", "/tmp", map[string]interface{}{"input": map[string]interface{}{"workdir": cdir, "patch": patch}})},
		{"apply_patch args.workdir", toolEv("apply_patch", "/tmp", map[string]interface{}{"args": map[string]interface{}{"workdir": cdir, "patch": patch}})},
		{"apply_patch 17 levels deep", toolEv("apply_patch", "/tmp", deep)},
		{"apply_patch key dir", toolEv("apply_patch", "/tmp", map[string]interface{}{"patch": patch, "dir": cdir})},
		{"apply_patch key directory", toolEv("apply_patch", "/tmp", map[string]interface{}{"patch": patch, "directory": cdir})},
		{"apply_patch key root", toolEv("apply_patch", "/tmp", map[string]interface{}{"patch": patch, "root": cdir})},
		{"apply_patch key path", toolEv("apply_patch", "/tmp", map[string]interface{}{"patch": patch, "path": cdir})},
	}
	// Each case runs with the hook in the event cwd and in /tmp.
	for _, c := range cases {
		c := c
		for _, hookDir := range []string{home, "/tmp"} {
			hookDir := hookDir
			t.Run(c.name+" hook in "+filepath.Base(hookDir), func(t *testing.T) {
				t.Chdir(hookDir)
				if got, reason := review090dRun(t, c.ev, file); got != "deny" {
					t.Errorf("decision %q (%s), want deny", got, reason)
				}
			})
		}
	}
}

// noCwd removes the cwd of an event.
func noCwd(ev map[string]interface{}) map[string]interface{} {
	delete(ev, "cwd")
	return ev
}

// Fable 1: a write under /proc/self/cwd is read in the working directory
// of the hook process, which can differ from the cwd of the event. The
// variable is the hook process directory and the event cwd; the target is
// the protected file in one case and a plain file in the other.
func TestReview090dProcSelfCwdWrite(t *testing.T) {
	home, cdir, file, _ := review090dTree(t)
	if err := os.MkdirAll(filepath.Join(home, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(cwd, fp string) map[string]interface{} {
		ev := toolEv("Write", cwd, map[string]interface{}{"file_path": fp, "content": "x"})
		if cwd == "" {
			delete(ev, "cwd")
		}
		return ev
	}
	cases := []struct {
		name, hookDir, eventCwd, target, want string
	}{
		{"hook in home, event in home, P", home, home, "/proc/self/cwd/.claude/settings.json", "deny"},
		{"hook in home, no event cwd, P", home, "", "/proc/self/cwd/.claude/settings.json", "deny"},
		{"hook in home, event in repo, P", home, filepath.Join(home, "repo"), "/proc/self/cwd/.claude/settings.json", "deny"},
		{"hook in .claude, event in /usr, P", cdir, "/usr", "/proc/self/cwd/settings.json", "deny"},
		{"hook in /usr, event in .claude, P", "/usr", cdir, "/proc/self/cwd/settings.json", "deny"},
		{"hook in home, event in /usr, thread-self P", home, "/usr", "/proc/thread-self/cwd/.claude/settings.json", "deny"},
		{"hook in home, event in home, ../", home, home, "/proc/self/cwd/../x/settings.json", "deny"},
		{"hook in home, event in home, safe.txt", home, home, "/proc/self/cwd/safe.txt", "allow"},
		{"hook in /tmp, event in /tmp, safe.txt", "/tmp", "/tmp", "/proc/self/cwd/safe.txt", "allow"},
		{"hook in /tmp, no event cwd, safe.txt", "/tmp", "", "/proc/self/cwd/safe.txt", "allow"},
		{"hook in home, event in /tmp, safe.txt", home, "/tmp", "/proc/self/cwd/safe.txt", "allow"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			pol, err := filepath.Abs(review090bShellPolicy())
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(c.hookDir)
			got, reason := review090bRun(t, write(c.eventCwd, c.target), pol, "-protect-path", file)
			if (c.want == "deny") != (got == "deny") {
				t.Errorf("decision %q (%s), want %s", got, reason, c.want)
			}
		})
	}
}

func TestReview090dNoFalsePositives(t *testing.T) {
	home, _, file, dirs := review090dTree(t)
	L := "{json,{1..70}}"
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// Gemini 6: a read from a file onto standard input, then a stream.
		{"< file 2>/dev/stderr", bashEv("grep foo < /etc/hosts 2>/dev/stderr", home)},
		{"< file > /dev/stdout", bashEv("cat < /etc/hosts > /dev/stdout", home)},
		{"< file 2>/dev/fd/2", bashEv("tr a b < /etc/hosts 2>/dev/fd/2", home)},
		{"< file 2>&1 > /dev/stdout", bashEv("cat < /etc/hosts 2>&1 > /dev/stdout", home)},
		// Plain directories and command texts that name no protected path.
		{"70 directories", bashEv("ls "+strings.Join(dirs, " "), home)},
		{"cd $D to a plain directory", bashEv("D=free; cd $D; python3 w.py x."+L, home)},
		{"env -Cfree ../x.json", bashEv("env -Cfree python3 w.py ../x.json", home)},
		{"eval 'echo {1..70}'", bashEv("eval 'echo {1..70}'", home)},
		{"quoted braces then a sequence", bashEv(`echo "{a,b}" {1..70}`, home)},
		{"zsh --emulate sh -c ls", bashEv("zsh --emulate sh -c 'ls'", home)},
		{"fish -C with a plain variable", bashEv(`fish -C"echo $HOME" -c true`, home)},
		{"fish -o /tmp/fish.log", bashEv("fish -o /tmp/fish.log -c true", home)},
		{"Write free/x.txt", toolEv("Write", home, map[string]interface{}{"file_path": "free/x.txt", "content": "x"})},
		{"redirect free/x.txt", bashEv("echo x > free/x.txt", home)},
		{"apply_patch free/notes.txt", toolEv("apply_patch", "/tmp", map[string]interface{}{"patch": review090cPatch("notes.txt"), "workdir": filepath.Join(home, "free")})},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got, reason := review090dRun(t, c.ev, file); got == "deny" {
				t.Errorf("decision deny (%s), want not deny", reason)
			}
		})
	}
}

// Pathological words end fast with a decision and no panic. Over-deny is
// acceptable here; a crash or a long run is not.
func TestReview090dPathologicalWords(t *testing.T) {
	home, _, file, _ := review090dTree(t)
	cases := []struct {
		name, cmd string
	}{
		{"7000 split characters", "python3 w.py " + strings.Repeat("a=:@,+%", 7000) + "{1..70}"},
		{"100 commas then 4096 words", "python3 w.py " + strings.Repeat("a,", 100) + "x." + strings.Repeat("{a,b}", 12)},
		{"control bytes", "python3 w.py " + strings.Repeat("\x01\x02\x7f\x1b", 5000) + "{a,{1..70}}"},
		{"7500 open lists", "echo " + strings.Repeat("{a,{", 7500)},
		{"40000 open braces", "echo " + strings.Repeat("{", 40000)},
		{"10000 nested lists", "echo " + strings.Repeat("{a,", 10000) + strings.Repeat("}", 10000)},
		{"5000 quoted lists in a redirect", "echo x > " + strings.Repeat("''{a,", 5000) + strings.Repeat("}", 5000)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// The floor, the check of 22ed838, spends most of the time on
			// "40000 open braces": 0.63 s of 1.03 s in a race build on 2
			// cores. So that case has 5 s, and every other case 2 s.
			limit := 2 * time.Second
			if c.name == "40000 open braces" {
				limit = 5 * time.Second
			}
			start := time.Now()
			got, reason := review090dRun(t, bashEv(c.cmd, home), file)
			review090Took(t, time.Since(start), limit, reason)
			if strings.Contains(reason, "did not end in") {
				t.Errorf("denied on the time limit: %s", reason)
			}
			if got != "" && got != "allow" && got != "deny" && got != "ask" {
				t.Errorf("decision %q", got)
			}
		})
	}
}
