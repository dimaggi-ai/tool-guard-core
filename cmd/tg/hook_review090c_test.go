package main

// Third-round regression tests for PR #93: the variants the review panel
// (2026-11-25, round 2) found still allowed, the false positives of the
// second round, and the dispatch and -escalate-as findings. Every case runs
// through the hook with the shipped policy, as a subtest of its own.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// review090cTree extends review090Tree: dlink is home/.claude through a
// link, pl is a link to /proc/self/cwd, and free/a is a plain directory.
func review090cTree(t *testing.T) (home, cdir, file string) {
	t.Helper()
	home, cdir, file = review090Tree(t)
	if err := os.Symlink(cdir, filepath.Join(home, "dlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/cwd", filepath.Join(home, "pl")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "free", "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home, cdir, file
}

func review090cPatch(target string) string {
	return "*** Begin Patch\n*** Update File: " + target + "\n@@\n+x\n*** End Patch"
}

func TestReview090cProtectedPathBypasses(t *testing.T) {
	home, cdir, file := review090cTree(t)
	x := "echo x > $X"
	write := func(cwd, fp string) map[string]interface{} {
		return toolEv("Write", cwd, map[string]interface{}{"file_path": fp, "content": "x"})
	}
	patchEv := func(cwd string, input map[string]interface{}) map[string]interface{} {
		return toolEv("apply_patch", cwd, input)
	}
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// A brace list in quotes, nested, in a redirect target.
		{"redirect ''{P,{a}}{,{c}}", bashEv("echo x > ''{"+file+",{a}}{,{c}}", home)},
		{"redirect ''{settings.json,{a}}", bashEv("echo x > ''{settings.json,{a}}", cdir)},
		{"redirect {'settings.json',{a}}", bashEv("echo x > {'settings.json',{a}}", cdir)},
		{"redirect ''{settings,{a}}.{json,{b}}", bashEv("echo x > ''{settings,{a}}.{json,{b}}", cdir)},
		{"cp ''{settings.json,{a}}", bashEv("cp /etc/hosts ''{settings.json,{a}}", cdir)},
		// apply_patch: work directory keys, other patch keys, nested values.
		{"apply_patch absolute workdir", patchEv("/tmp", map[string]interface{}{"command": review090cPatch("settings.json"), "workdir": cdir})},
		{"apply_patch relative working_dir", patchEv(home, map[string]interface{}{"command": review090cPatch("settings.json"), "working_dir": ".claude"})},
		{"apply_patch absolute working_directory", patchEv("/tmp", map[string]interface{}{"command": review090cPatch("settings.json"), "working_directory": cdir})},
		{"apply_patch absolute cwd", patchEv("/tmp", map[string]interface{}{"command": review090cPatch("settings.json"), "cwd": cdir})},
		{"apply_patch absolute workingDir", patchEv("/tmp", map[string]interface{}{"command": review090cPatch("settings.json"), "workingDir": cdir})},
		{"apply_patch absolute work_dir", patchEv("/tmp", map[string]interface{}{"command": review090cPatch("settings.json"), "work_dir": cdir})},
		{"apply_patch key content", patchEv(home, map[string]interface{}{"content": review090cPatch(file)})},
		{"apply_patch key changes", patchEv(home, map[string]interface{}{"changes": review090cPatch(file)})},
		{"apply_patch key args", patchEv(home, map[string]interface{}{"args": review090cPatch(file)})},
		{"apply_patch nested input.patch", patchEv(home, map[string]interface{}{"input": map[string]interface{}{"patch": review090cPatch(file)}})},
		{"apply_patch args array", patchEv(home, map[string]interface{}{"args": []interface{}{review090cPatch(file)}})},
		// /dev directories other than /dev/fd, and links into /proc.
		{"redirect /dev/shm/../fd/../cwd", bashEv("echo x > /dev/shm/../fd/../cwd/settings.json", cdir)},
		{"Write /dev/shm/../fd/../cwd", write(cdir, "/dev/shm/../fd/../cwd/settings.json")},
		{"Write /dev/shm/../fd/3", write(cdir, "/dev/shm/../fd/3/settings.json")},
		{"exec 3< and /dev/shm/../fd/3", bashEv("exec 3< "+cdir+" && echo x > /dev/shm/../fd/3/settings.json", "/tmp")},
		{"cp to /dev/mqueue/../fd/3", bashEv("cp /etc/hosts /dev/mqueue/../fd/3/settings.json 3<.", cdir)},
		{"Write /proc/self/fd/3", write("/tmp", "/proc/self/fd/3")},
		{"Write through a link to /proc/self/cwd", write(cdir, filepath.Join(home, "pl", "settings.json"))},
		{"cp through a link to /proc/self/cwd", bashEv("cp /etc/hosts "+filepath.Join(home, "pl", "settings.json"), cdir)},
		{"long list under /proc/self/{cwd,...}", bashEv("python3 w.py /proc/self/{cwd,{1..70}}/settings.json", cdir)},
		// Options of fish read the wrong way.
		{"fish --init-command= then -c", bashEv("fish --init-command='echo hi' -c '"+x+"'", home)},
		{"fish -C'...' then -c", bashEv("fish -C'echo C' -c '"+x+"'", home)},
		{"fish -p FILE -C", bashEv("fish -p /tmp/p -C '"+x+"'", home)},
		{"fish --profile FILE -c", bashEv("fish --profile /tmp/p -c '"+x+"'", home)},
		{"fish --features VALUE -C", bashEv("fish --features qmark-noglob -C '"+x+"'", home)},
		{"fish --co", bashEv("fish --co '"+x+"'", home)},
		{"fish --c", bashEv("fish --c '"+x+"'", home)},
		{"fish --i", bashEv("fish --i '"+x+"'", home)},
		{"fish -d VALUE -C", bashEv("fish -d 3 -C '"+x+"'", home)},
		{"fish -o FILE -C", bashEv("fish -o /tmp/log -C '"+x+"'", home)},
		{"fish --debug VALUE -C", bashEv("fish --debug 3 -C '"+x+"'", home)},
		{"fish --debug-output FILE -c", bashEv("fish --debug-output /tmp/l -c '"+x+"'", home)},
		{"fish --profile-startup FILE -c", bashEv("fish --profile-startup /tmp/p -c '"+x+"'", home)},
		{"fish -f VALUE -c", bashEv("fish -f no-x -c '"+x+"'", home)},
		{"fish -o $X writes a file", bashEv("fish -o $X -c true", home)},
		{"fish --debug-output=P writes P", bashEv("fish --debug-output="+file+" -c true", home)},
		// A positional parameter the -c text runs.
		{"bash -c eval $1", bashEv("bash -c 'eval \"$1\"' _ '"+x+"'", home)},
		// A long brace list whose first part is empty or starts with a
		// name under the working directory.
		{"long list {.claude,...}", bashEv("python3 w.py {.claude,{1..70}}/settings.json", home)},
		{"tar -cf {.claude,...}", bashEv("tar -cf {.claude,{1..70}}/settings.json /etc/hosts", home)},
		{"long list {{1..70},.claude}", bashEv("python3 w.py {{1..70},.claude}/settings.json", home)},
		{"long list \"\"{.claude,...}", bashEv("python3 w.py \"\"{.claude,{1..70}}/settings.json", home)},
		{"long list {settings,...}.json", bashEv("python3 w.py {settings,{1..70}}.json", cdir)},
		// A long brace list after a part that ends in a dot.
		{"long list .{claude,...}", bashEv("python3 w.py .{claude,{1..70}}/settings.json", home)},
		{"long list .{claude/settings.json,...}", bashEv("python3 w.py .{claude/settings.json,{1..70}}", home)},
		{"long list lnk/.{.,...}", bashEv("python3 w.py lnk/.{.,{1..70}}/settings.json", home)},
		{"long list out=.{claude,...}", bashEv("python3 w.py out=.{claude,{1..70}}/settings.json", home)},
		{"tar -cf.{claude,...}", bashEv("tar -cf.{claude,{1..70}}/settings.json /etc/hosts", home)},
		// A long brace list after a separator that is not part of a path.
		{"long list after a,", bashEv("python3 w.py a,.claude/settings.{json,{1..70}}", home)},
		{"long list after a+", bashEv("python3 w.py a+.claude/settings.{json,{1..70}}", home)},
		{"long list after a%", bashEv("python3 w.py a%.claude/settings.{json,{1..70}}", home)},
		{"long list after \"x\"", bashEv("python3 w.py \"x\".claude/settings.{json,{1..70}}", home)},
		{"long list after a, and a link", bashEv("python3 w.py a,dlink/settings.{json,{1..70}}", home)},
		// .. over a link when an option names the directory.
		{"env -C lnk", bashEv("env -C lnk python3 w.py ../settings.{json,{1..70}}", home)},
		{"env --chdir=lnk", bashEv("env --chdir=lnk python3 w.py ../settings.{json,{1..70}}", home)},
		{"tar -C lnk", bashEv("tar -C lnk -cf ../settings.{json,{1..70}} /etc/hosts", home)},
		{"git -C lnk", bashEv("git -C lnk apply ../settings.{json,{1..70}}", home)},
		// A link named inside the list, and .. that comes from a variable.
		{"long list {dlink,...}", bashEv("python3 w.py {dlink,{1..70}}/settings.json", home)},
		{"long list lnk/$D with D=..", bashEv("D=.. python3 w.py lnk/$D/settings.{json,{1..70}}", home)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got, reason := review090bRun(t, c.ev, review090bShellPolicy(), "-protect-path", file); got != "deny" {
				t.Errorf("decision %q (%s), want deny", got, reason)
			}
		})
	}
}

func TestReview090cNoFalsePositives(t *testing.T) {
	home, cdir, file := review090cTree(t)
	free := filepath.Join(home, "free")
	dd40 := strings.Repeat(free+"/../", 40)
	da40 := strings.Repeat(free+"/a/../../", 40)
	b4096 := strings.Repeat("{a,b}", 12)
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// The empty word after the text of -c is a positional parameter.
		{"bash -c CMD ''", bashEv("bash -c 'echo ok' ''", home)},
		{"sh -c CMD ''", bashEv("sh -c 'ls' ''", home)},
		{"bash -c CMD '' ''", bashEv("bash -c 'echo ok' '' ''", home)},
		{"fish -c CMD ''", bashEv("fish -c 'echo ok' ''", home)},
		{"bash ''", bashEv("bash ''", home)},
		// Options that only change how the shell runs: the read is read.
		{"bash -e -c read", bashEv("bash -e -c 'cat "+file+"'", home)},
		{"bash -xc read", bashEv("bash -xc 'cat "+file+"'", home)},
		{"bash --norc -c read", bashEv("bash --norc -c 'cat "+file+"'", home)},
		{"bash -c read --arg", bashEv("bash -c 'cat "+file+"' --arg", home)},
		{"sh -c read ''", bashEv("sh -c 'cat "+file+"' ''", home)},
		// The streams of the process and files under /proc that are not a
		// directory of a process.
		{"> /dev/stderr", bashEv("echo x > /dev/stderr", home)},
		{"> /dev/stdout", bashEv("echo x > /dev/stdout", home)},
		{">> /dev/stderr", bashEv("echo err >> /dev/stderr", home)},
		{"2>/dev/stderr", bashEv("make 2>/dev/stderr", home)},
		{"> /dev/fd/1", bashEv("echo x > /dev/fd/1", home)},
		{"> /dev/fd/2", bashEv("echo x >/dev/fd/2", home)},
		{"> /proc/sys/vm/drop_caches", bashEv("echo 3 > /proc/sys/vm/drop_caches", home)},
		{"> /proc/self/oom_score_adj", bashEv("echo x > /proc/self/oom_score_adj", home)},
		{"Write /proc/self/cwd/safe.txt", toolEv("Write", "/tmp", map[string]interface{}{"file_path": "/proc/self/cwd/safe.txt", "content": "x"})},
		// Long brace lists that name no protected path.
		{"long list under /tmp/unrelated", bashEv("python3 w.py /tmp/unrelated/settings.{json,{1..70}}", cdir)},
		{"long list under /var/backup/.claude", bashEv("python3 w.py /var/backup/.claude/settings.{json,{1..70}}", home)},
		{"long list after $OUT/..", bashEv("python3 w.py $OUT/../x.{json,{1..70}}", home)},
		{"long list after \"$PWD\"/..", bashEv("python3 w.py \"$PWD\"/../x.{json,{1..70}}", home)},
		{"long list after /var/run/..", bashEv("python3 w.py /var/run/../x.{json,{1..70}}", home)},
		{"long list after a missing name", bashEv("python3 w.py afile/../x.{json,{1..70}}", home)},
		{"sequence then ..", bashEv("python3 w.py free/{1..70}/../x", home)},
		{"sequence then .. under a missing directory", bashEv("python3 w.py nofree/{1..70}/../x", home)},
		{"40 free/.. and 4096 words", bashEv("python3 w.py "+dd40+"x."+b4096, home)},
		{"40 free/a/../.. and 4096 words", bashEv("python3 w.py "+da40+"x."+b4096, home)},
		// apply_patch targets under directories of the protected-path rules.
		{"apply_patch proc/x.c", toolEv("apply_patch", home, map[string]interface{}{"command": review090cPatch("proc/x.c")})},
		{"apply_patch dev/fd/notes.md", toolEv("apply_patch", home, map[string]interface{}{"command": review090cPatch("dev/fd/notes.md")})},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got, reason := review090bRun(t, c.ev, review090bShellPolicy(), "-protect-path", file); got == "deny" {
				t.Errorf("decision deny (%s), want not deny", reason)
			}
		})
	}
}

// A relative apply_patch target is placed under the working directory, not
// under the root: bin/run.sh in a repository is not /bin/run.sh.
func TestReview090cApplyPatchRelativeTargetsWritesPolicy(t *testing.T) {
	pol := filepath.Join("..", "..", "policies", "coding_agent_writes.yaml")
	for _, target := range []string{"bin/run.sh", "etc/app.conf", "lib/foo.rb", "usr/local/x", "var/log/x", "var/data.json"} {
		for _, cwd := range []string{"/repo", ""} {
			target, cwd := target, cwd
			t.Run(target+" cwd="+cwd, func(t *testing.T) {
				ev := toolEv("apply_patch", cwd, map[string]interface{}{"command": review090cPatch(target)})
				if cwd == "" {
					delete(ev, "cwd")
				}
				if got, reason := review090bRun(t, ev, pol); got == "deny" {
					t.Errorf("decision deny (%s), want not deny", reason)
				}
			})
		}
	}
}

// A relative apply_patch target with no cwd in the event is read under the
// working directory of the hook, as a write tool path is.
func TestReview090cApplyPatchNoCwd(t *testing.T) {
	home, _, file := review090cTree(t)
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
	pol, err := filepath.Abs(filepath.Join(saved, "..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_shell.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{".claude/settings.json", "lnk/../settings.json"} {
		target := target
		t.Run(target, func(t *testing.T) {
			ev := toolEv("apply_patch", "", map[string]interface{}{"command": review090cPatch(target)})
			delete(ev, "cwd")
			if got, reason := review090bRun(t, ev, pol, "-protect-path", file); got != "deny" {
				t.Errorf("decision %q (%s), want deny", got, reason)
			}
		})
	}
}

// -dispatch reads a tool as a shell command only when it is a shell tool
// or carries a command parameter. Other tools keep the policy decision.
func TestReview090cDispatchSkipsToolsWithoutCommand(t *testing.T) {
	disp := []string{"-dispatch", "gh_read"}
	for _, c := range []struct {
		tool  string
		input map[string]interface{}
	}{
		{"Glob", map[string]interface{}{"pattern": "**/*.go"}},
		{"Grep", map[string]interface{}{"pattern": "foo"}},
		{"Task", map[string]interface{}{"prompt": "x"}},
		{"mcp__github__list_issues", map[string]interface{}{"repo": "x"}},
		{"TodoWrite", map[string]interface{}{"todos": []interface{}{}}},
		{"WebSearch", map[string]interface{}{"query": "x"}},
	} {
		c := c
		t.Run(c.tool, func(t *testing.T) {
			if got, reason := review090bRun(t, toolEv(c.tool, "/tmp", c.input), review090bShellPolicy(), disp...); got != "allow" {
				t.Errorf("decision %q (%s), want allow", got, reason)
			}
		})
	}
	t.Run("unlisted tool with a command", func(t *testing.T) {
		ev := toolEv("run_terminal_cmd", "/tmp", map[string]interface{}{"command": "python3 x.py"})
		if got, _ := review090bRun(t, ev, review090bShellPolicy(), disp...); got != "ask" {
			t.Errorf("decision %q, want ask", got)
		}
	})
}

// The reason of an escalation returned as a denial names the rule.
func TestReview090cEscalateAsReasonNamesRule(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	for _, val := range []string{"deny", "bogus"} {
		val := val
		t.Run(val, func(t *testing.T) {
			out, _ := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", val)
			dec, reason := hookDecisionReason(t, out)
			if dec != "deny" || !strings.Contains(reason, "Escalated by: [escalate-git]") || !strings.Contains(reason, "git needs review") {
				t.Errorf("decision %q reason %q, want deny naming the rule escalate-git and its text", dec, reason)
			}
		})
	}
}
