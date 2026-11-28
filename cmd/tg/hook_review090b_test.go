package main

// Second-round regression tests for PR #93: the variants the review panel
// (2026-11-25) found still allowed, and the false positives the first round
// added. Cases are subtests so each one reports on its own.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func review090bRun(t *testing.T, ev map[string]interface{}, pol string, extra ...string) (decision, reason string) {
	t.Helper()
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-policy", pol, "-mode", "enforcement", "-fail-closed"}, extra...)
	var buf bytes.Buffer
	if code := runHook(args, bytes.NewReader(payload), &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(buf.String()) == "" {
		return "", ""
	}
	return hookDecisionReason(t, buf.String())
}

func review090bShellPolicy() string {
	return filepath.Join("..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_shell.yaml")
}

func toolEv(tool, cwd string, input map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd, "tool_input": input}
}

func TestReview090bProtectedPathBypasses(t *testing.T) {
	home, cdir, file := review090Tree(t)
	// dlink is home/.claude through a link, with no "..".
	if err := os.Symlink(cdir, filepath.Join(home, "dlink")); err != nil {
		t.Fatal(err)
	}
	// ub is home/u/bin through a link with a relative target.
	if err := os.MkdirAll(filepath.Join(home, "u", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("u", "bin"), filepath.Join(home, "ub")); err != nil {
		t.Fatal(err)
	}
	patch := func(lines ...string) string {
		return "*** Begin Patch\n" + strings.Join(lines, "\n") + "\n*** End Patch"
	}
	upd := patch("*** Update File: "+file, "@@", "+x")
	long := "{json,{1..70}}"
	write := func(cwd, fp string) map[string]interface{} {
		return toolEv("Write", cwd, map[string]interface{}{"file_path": fp, "content": "x"})
	}
	cases := []struct {
		name string
		ev   map[string]interface{}
	}{
		// Nested single-item brace group in a redirect target.
		{"redirect P.{json,{a}}", bashEv("echo x > "+cdir+"/settings.{json,{a}}", home)},
		{"redirect {P,{a}}", bashEv("echo x > {"+file+",{a}}", home)},
		{"redirect ''{P,{a}}", bashEv("echo x > ''{"+file+",{a}}", home)},
		// fish options that carry a command, with an unresolved write target.
		{"fish -C X -c", bashEv("fish -C 'echo hi' -c 'echo x > $X'", home)},
		{"fish --init-command X -c", bashEv("fish --init-command 'echo hi' -c 'echo x > $X'", home)},
		{"fish -iC", bashEv("fish -iC 'echo x > $X'", home)},
		{"fish --init-c", bashEv("fish --init-c 'echo x > $X'", home)},
		{"fish -c ok -C glued", bashEv("fish -c 'echo ok' -C'echo x > $X'", home)},
		// Long brace list: relative path with ".." after a link.
		{"rel lnk/../P.long", bashEv("python3 w.py lnk/../settings."+long, home)},
		{"out=rel lnk/../P.long", bashEv("python3 w.py out=lnk/../settings."+long, home)},
		{"tar -cf rel lnk/../P.long", bashEv("tar -cflnk/../settings."+long+" /etc/hosts", home)},
		// Long brace list: relative path glued to a short option.
		{"tar -cf rel no slash", bashEv("tar -cfsettings."+long+" /etc/hosts", cdir)},
		{"tar -cf rel with slash", bashEv("tar -cf.claude/settings."+long+" /etc/hosts", home)},
		{"python -o rel", bashEv("python3 w.py -osettings."+long, cdir)},
		// Long brace list: a link with no "..", and an absolute path inside the braces.
		{"dlink/P.long", bashEv("python3 w.py dlink/settings."+long, home)},
		{"{abs lnk/..,{1..70}}/P", bashEv("python3 w.py {"+home+"/lnk/..,{1..70}}/settings.json", home)},
		// Long brace list: a link, "..", then more directories (lnk is
		// .claude/sub, so lnk/../.. is home physically, its parent lexically).
		{"rel lnk/../../.claude/P.long", bashEv("python3 w.py lnk/../../.claude/settings."+long, home)},
		{"abs lnk/../../.claude/P.long", bashEv("python3 w.py "+home+"/lnk/../../.claude/settings."+long, "/tmp")},
		{"rel ub/../../.claude/P.long", bashEv("python3 w.py ub/../../.claude/settings."+long, home)},
		{"abs ub/../../.claude/P.long", bashEv("python3 w.py "+home+"/ub/../../.claude/settings."+long, "/tmp")},
		{"rel from / ub/../../.claude/P.long", bashEv("python3 w.py "+strings.TrimPrefix(home, "/")+"/ub/../../.claude/settings."+long, "/")},
		{"rel from / lnk/../P.long", bashEv("python3 w.py "+strings.TrimPrefix(home, "/")+"/lnk/../settings."+long, "/")},
		{"redirect lnk/../../.claude/P.{json,}", bashEv("echo x > "+home+"/lnk/../../.claude/settings.{json,}", "/tmp")},
		// Long brace list after other separators.
		{"a:P.long", bashEv("python3 w.py a:"+cdir+"/settings."+long, home)},
		{"@P.long", bashEv("python3 w.py @"+cdir+"/settings."+long, home)},
		// /proc and /dev/fd reached from the working directory, or hidden behind "..".
		{"Write cwd=/proc/self cwd/P", write("/proc/self", "cwd/settings.json")},
		{"Write cwd=/dev/fd/3 P", write("/dev/fd/3", "settings.json")},
		{"Write /dev/pts/../fd/../cwd", write(cdir, "/dev/pts/../fd/../cwd/settings.json")},
		{"bash /proc/self/{cwd,long}", bashEv("python3 w.py /proc/self/{cwd,{1..70}}/settings.json", cdir)},
		{"bash /proc/self/{cwd,{a}}", bashEv("python3 w.py /proc/self/{cwd,{a}}/settings.json", cdir)},
		{"bash /dev/pts/../fd/../cwd", bashEv("echo x > /dev/pts/../fd/../cwd/settings.json", cdir)},
		{"bash /dev/stdin/P", bashEv("echo x < "+cdir+" > /dev/stdin/settings.json", "/tmp")},
		{"bash /dev/stderr/P", bashEv("cp /etc/hosts /dev/stderr/settings.json 2< "+cdir, "/tmp")},
		// apply_patch: other patch-text keys and a work directory.
		{"apply_patch patch_text", toolEv("apply_patch", home, map[string]interface{}{"patch_text": upd})},
		{"apply_patch patchText", toolEv("apply_patch", home, map[string]interface{}{"patchText": upd})},
		{"apply_patch diff", toolEv("apply_patch", home, map[string]interface{}{"diff": upd})},
		{"apply_patch text", toolEv("apply_patch", home, map[string]interface{}{"text": upd})},
		{"apply_patch body", toolEv("apply_patch", home, map[string]interface{}{"body": upd})},
		{"apply_patch workdir", toolEv("apply_patch", home, map[string]interface{}{
			"command": patch("*** Update File: settings.json", "@@", "+x"), "workdir": ".claude"})},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got, _ := review090bRun(t, c.ev, review090bShellPolicy(), "-protect-path", file); got != "deny" {
				t.Errorf("decision %q, want deny", got)
			}
		})
	}
}

// Commands the first round of fixes denied although they never write a
// protected path.
func TestReview090bNoFalsePositives(t *testing.T) {
	home, _, file := review090Tree(t)
	free := filepath.Join(home, "free")
	if err := os.MkdirAll(free, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, cmd string }{
		{"bash -c read -i", "bash -c 'cat " + file + "' -i"},
		{"fish -c read --init-command read", "fish -c 'cat " + file + "' --init-command 'cat " + file + "'"},
		{"quoted brace redirect", "echo x > '{" + file + ",}'"},
		{"bash --rcfile=$HOME", "bash --rcfile=\"$HOME/.bashrc\" -c 'ls'"},
		{"sh configure --prefix=$PREFIX", "sh ./configure --prefix=$PREFIX"},
		{"bash install --dir=$PWD", "bash install.sh --dir=\"$PWD/out\""},
		{"bash deploy --host=$HOST", "bash scripts/deploy.sh --host=$HOST --skip-build"},
		// Not a read-only program, so the long-list path check really runs.
		{"free/../free long list", "python3 w.py " + free + "/../free/set.{json,{1..70}}"},
		// ".." right before the brace word, no link anywhere.
		{"free/../x long list", "python3 w.py " + free + "/../x.{json,{1..70}}"},
		{"rel free/../x long list", "python3 w.py free/../x.{json,{1..70}}"},
		{"free/a/../../x long list", "python3 w.py " + free + "/a/../../x.{json,{1..70}}"},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got, reason := review090bRun(t, bashEv(c.cmd, home), review090bShellPolicy(), "-protect-path", file); got == "deny" {
				t.Errorf("decision deny (%s), want not deny", reason)
			}
		})
	}
}

// apply_patch paths with "." or empty parts must still match the
// context-files policy, as they did when the target was cleaned.
func TestReview090bApplyPatchDotPartsContextPolicy(t *testing.T) {
	pol := filepath.Join("..", "..", "policies", "coding_agent_context_files.yaml")
	for _, target := range []string{".claude/./settings.json", ".claude//settings.json"} {
		target := target
		t.Run(target, func(t *testing.T) {
			ev := toolEv("apply_patch", "/repo", map[string]interface{}{
				"command": "*** Begin Patch\n*** Update File: " + target + "\n@@\n+x\n*** End Patch"})
			if got, _ := review090bRun(t, ev, pol); got == "allow" || got == "" {
				t.Errorf("decision %q, want ask or deny", got)
			}
		})
	}
}

func TestReview090bDispatch(t *testing.T) {
	_, _, file := review090Tree(t)
	disp := []string{"-protect-path", file, "-dispatch", "gh_read"}
	// A command array keeps the malformed-input deny under -dispatch.
	t.Run("array command", func(t *testing.T) {
		ev := toolEv("shell", "/tmp", map[string]interface{}{"command": []interface{}{"bash", "-lc", "echo x > " + file}})
		if got, _ := review090bRun(t, ev, review090bShellPolicy(), disp...); got != "deny" {
			t.Errorf("decision %q, want deny", got)
		}
	})
	// Shell tools with other names are dispatched too.
	for _, tool := range []string{"run_terminal_cmd", "execute_command"} {
		tool := tool
		t.Run(tool+" unclassified", func(t *testing.T) {
			ev := toolEv(tool, "/tmp", map[string]interface{}{"command": "python3 script.py"})
			if got, _ := review090bRun(t, ev, review090bShellPolicy(), disp...); got != "ask" {
				t.Errorf("decision %q, want ask", got)
			}
		})
	}
	// The gh read is allowed by the dispatcher, not by passthrough.
	t.Run("Bash gh pr list reason", func(t *testing.T) {
		got, reason := review090bRun(t, bashEv("gh pr list", "/tmp"), review090bShellPolicy(), disp...)
		if got != "allow" || !strings.Contains(reason, "verified gh read") {
			t.Errorf("decision %q reason %q, want allow by the gh read dispatcher", got, reason)
		}
	})
}

// A mistyped -escalate-as value is named in the reason.
func TestReview090bEscalateAsReasonNamesValue(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	out, _ := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", "bogus")
	if _, reason := hookDecisionReason(t, out); strings.Contains(reason, "-escalate-as deny") || !strings.Contains(reason, "bogus") {
		t.Errorf("reason %q, want it to name the value bogus", reason)
	}
}
