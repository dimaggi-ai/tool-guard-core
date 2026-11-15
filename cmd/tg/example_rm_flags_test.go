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
		{`rm -- -f`, "ask"}, // Known fail-closed operand match.
		{`rm "a -f b"`, "allow"},
		{`rm 'a -r b'`, "allow"},
		{`rm "a -r b"; cd /`, "allow"},
		{`rm 'a -f b' -r build`, "ask"},
		{`rm "a b" -f x`, "ask"},
		{`rm a\ b -f x`, "ask"},
		{`rm "-f"suffix`, "allow"},
		{`rm '-r'suffix; cd /`, "allow"},
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
