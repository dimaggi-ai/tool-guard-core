package main

import (
	"path/filepath"
	"testing"
)

// Evaluate the shipped YAML through the real hook and Go RE2 engine. No shell
// command in this table is executed.
func TestExampleRMFlagWords(t *testing.T) {
	rows := []struct{ command, want string }{
		{`rm -rf /`, "deny"},
		{`rm -r -f /`, "deny"},
		{`rm --recursive --force /`, "deny"},
		{`rm -fR /home`, "deny"},
		{`rm -rf "/"`, "deny"},
		{`rm -rf /etc`, "deny"},
		{`rm -rf $HOME`, "deny"},
		{`rm -rf ~`, "deny"},
		{`/bin/rm -rf /`, "deny"},
		{`rm -rf /*`, "deny"},
		{`sudo rm -rf /`, "deny"},
		{`rm -v -rf /`, "deny"},
		{`rm -rf -- /`, "deny"},
		{`rm /etc -rf`, "deny"},
		{`rm "-rf" /`, "deny"},
		{`rm '-rf' /`, "deny"},
		{`rm -f file`, "ask"},
		{`rm -rf build`, "ask"},
		{`rm --force x`, "ask"},
		{`rm -fv x`, "ask"},
		{`rm -rf /tmp/scratch/build`, "ask"},
		{`rm -rf $HOME/projects`, "ask"},
		{`rm /run/user/1000/tg-verify.ab12/ws/escalate-target.txt`, "allow"},
		{`rm /tmp/my-file.txt`, "allow"},
		{`rm my-report.txt; cd ~`, "allow"},
		{`rm x && grep -rn foo /`, "allow"},
		{`rm /run/user/1000/tg-verify.ab12/ws/escalate-target.txt && echo "removed" || echo "not present / not removed"`, "allow"},
		{`rm x; grep -f patterns /`, "allow"},
		{`rm x | grep -r foo /`, "allow"},
		{"rm x\ngrep -rf patterns /", "allow"},
		{"rm\n-f x", "allow"},
		{"rm x\n-f /", "allow"},
		{`rm x -f; echo done`, "ask"},
		{`rm x -r& echo done`, "ask"},
		{`rm x -f| cat`, "ask"},
		{`rm -- -f`, "ask"}, // Known false positive: a flag-like operand after -- is escalated.
		{`rm "a -f b"`, "allow"},
		{`rm 'a -r b'`, "allow"},
		{`rm "a -r b"; cd /`, "allow"},
		{`rm 'a -f b' -r build`, "ask"},
		{`rm "a b" -f x`, "ask"},
		{`rm a\ b -f x`, "ask"},
		// The shell removes quotes and backslashes, so these spellings are still the
		// flag. They match on purpose.
		{`rm "-f"suffix`, "ask"},
		{`rm '-r'suffix; cd /`, "deny"},
		{`rm \-rf /tmp/x`, "ask"},
		{`rm \-rf /`, "deny"},
		{`rm -"rf" /tmp/x`, "ask"},
		{`rm -r''f /tmp/x`, "ask"},
		{`rm -\rf /tmp/x`, "ask"},
		{`rm $'-rf' /tmp/x`, "ask"},
		{`rm -$'rf' /`, "deny"},
		{`rm -r$'f' /tmp/x`, "ask"},
		{`rm -$"rf" /tmp/x`, "ask"},
		{`rm --$'recursive' /`, "deny"},
		{`rm /tmp/a$b-r`, "allow"},
		{`rm -fr${EMPTY} /tmp/x`, "ask"},
		{`rm -r${EMPTY} /`, "deny"},
		{`rm -v${X}f /tmp/x`, "ask"},
		{`rm -r$(true) /`, "deny"},
		{`rm -$(:)r /`, "deny"},
		{`rm -$(:;)r /`, "deny"},
		{`rm -$(echo a b)f /tmp/x`, "ask"},
		{"rm -$(:\n:)r /", "deny"},
		{`rm -v$(:;)f$(: |:) /tmp/x`, "ask"},
		{`rm --$(:;)recursive /`, "deny"},
		{`rm --$(:;)force x`, "ask"},
		{`rm --$(:;)verbose x`, "allow"},
		// Known limit, stated in the policy comment: a parenthesis inside the
		// substitution ends the match, so these flags are missed.
		{`rm -$(: ')'; :)r /tmp/x`, "allow"},
		{`rm -$(: $(:); :)f /tmp/x`, "allow"},
		{`rm -v$(:;) /tmp/x`, "allow"},
		{`rm -i $(echo a b) x`, "allow"},
		{`rm -$(:)f /tmp/x`, "ask"},
		{`(rm -$(:)f x)`, "ask"},
		{`(rm -v x)`, "allow"},
		{`rm --recursive${X} /`, "deny"},
		{`rm --force=1 x`, "ask"},
		{`rm -"r" /`, "deny"},
		{`rm -"f" /tmp/x`, "ask"},
		{`rm -v${X} /tmp/x`, "allow"},
		{`rm --verbose --interactive x`, "allow"},
		{`rm --preserve-root x`, "allow"},
		{`rm -d dir`, "allow"},
		{"rm \\\n-f /tmp/tg-probe", "ask"},
		{"rm \\\n -rf /", "deny"},
		{"rm x \\\n-r /", "deny"},
		{"rm\t-rf /", "deny"},
		{`rm --rec /tmp/x`, "ask"},
		{`rm --r /`, "deny"},
		{`rm --f x`, "ask"},
		{`rm --verbose /tmp/my-file.txt`, "allow"},
		{`rm -v /tmp/x`, "allow"},
		{`rm -i x`, "allow"},
		{`(rm x -f)`, "ask"},
		{`(rm x); echo -f`, "allow"},
		{`rm $(printf x) -f`, "ask"},
		{`rm $(printf x) -r /`, "deny"},
	}
	for _, row := range rows {
		t.Run(row.command, func(t *testing.T) {
			out, code := runHookStr(t, exampleShellPayload("claude", row.command),
				"-policy", filepath.Join(exampleDir(t), "policy.yaml"))
			got := hookDecision(t, out)
			t.Logf("%q -> %s", row.command, got)
			if code != 0 || got != row.want {
				t.Errorf("decision = %q (exit %d), want %q; output=%s", got, code, row.want, out)
			}
		})
	}
}

func TestExampleRMProtectedDeletes(t *testing.T) {
	for _, command := range []string{`rm /guarded/file`, `unlink /guarded/file`, `find /guarded/file -delete`} {
		out, _ := runHookStr(t, exampleShellPayload("claude", command),
			"-policy", filepath.Join(exampleDir(t), "policy.yaml"), "-protect-path", "/guarded/file")
		if got := hookDecision(t, out); got != "deny" {
			t.Errorf("%q -> %q, want deny", command, got)
		}
	}
}
