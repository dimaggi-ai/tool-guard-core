package main

// verify-harnesses.sh makes paid model calls, so it cannot run in the test
// suite against real harnesses. These tests run the real script against stub
// executables named claude, codex and agy. A stub reads the hook configuration
// the script wrote, calls the configured hook with a payload in the harness's
// shape, and performs the tool call only when the hook answers allow. The
// tests cover what the script itself does: scratch handling, evidence
// reduction, failure detection and exit status. They say nothing about what a
// real harness does.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVerifyHarnessesPythonEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("verifier evidence tests use POSIX file permissions")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-m", "unittest", "discover", "-s",
		filepath.Join("..", "..", "examples", "coding-agent-guard"), "-p", "test_verify_harnesses.py", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python verifier evidence regressions failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

const verifyStubCanary = "CANARYSIGNIN0123456789abcdefghijklmnop"

const verifyStubHarness = `#!/usr/bin/env python3
import glob, json, os, re, subprocess, sys
name = os.path.basename(sys.argv[0])
args = sys.argv[1:]
if args == ["--version"]:
    print("0.0.0-stub")
    sys.exit(0)
signin = None
if name == "claude":
    prompt = args[1]
    home = os.environ["CLAUDE_CONFIG_DIR"]
    signin = os.path.join(home, ".credentials.json")
    groups = json.load(open(os.path.join(home, "settings.json")))["hooks"]["PreToolUse"]
elif name == "codex":
    prompt = args[-1]
    home = os.environ["CODEX_HOME"]
    signin = os.path.join(home, "auth.json")
    groups = json.load(open(os.path.join(home, "hooks.json")))["hooks"]["PreToolUse"]
    if "--dangerously-bypass-hook-trust" not in args:
        groups = []
else:
    prompt = [a for a in args if a.startswith("--print=")][0][len("--print="):]
    groups = json.load(open(".agents/hooks.json"))["toolguard-coding-agent-guard"]["PreToolUse"]
if signin and not os.path.exists(signin):
    print("stub: no sign-in file")
    sys.exit(3)
kind_file = os.environ.get("STUB_SIGNIN_KIND_FILE")
if kind_file and signin:
    open(kind_file, "a").write(("link" if os.path.islink(signin) else "file") + "\n")
if os.environ.get("STUB_REPLACE_LINK") == "1" and signin and os.path.islink(signin):
    text = open(signin).read()
    os.unlink(signin)
    open(signin, "w").write(text)
if os.environ.get("STUB_TRUNCATE_SIGNIN") == "1" and signin:
    open(signin, "w").write("changed-by-harness")
print("session 123e4567-e89b-12d3-a456-426614174000 for stub.user@example.com in " + os.getcwd())
if os.environ.get("STUB_LEAK") == "1" and signin:
    print(open(signin).read())
prompt = prompt.strip()
count_file = os.environ.get("STUB_COUNT_FILE")
if count_file:
    turn = int(open(count_file).read()) + 1 if os.path.exists(count_file) else 1
    open(count_file, "w").write(str(turn))
    if str(turn) == os.environ.get("STUB_SILENT_TURN"):
        print("stub: no tool call in this turn")
        sys.exit(0)
shell = re.match(r"Run exactly this shell command and nothing else: (.*)$", prompt)
write = re.match(r"Using your file-writing tool rather than a shell command, create the file (\S+) containing exactly: (.*)$", prompt)
extra = {"hook_event_name": "PreToolUse", "session_id": "123e4567-e89b-12d3-a456-426614174000",
         "transcript_path": os.path.expanduser("~/t.jsonl")}
if shell:
    cmd = shell.group(1)
    if name == "agy":
        payload = {"conversationId": "c-1", "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}
    else:
        payload = dict(extra, tool_name="Bash", tool_input={"command": cmd})
else:
    path, text = write.group(1), write.group(2)
    if name == "agy":
        payload = {"conversationId": "c-1", "toolCall": {"name": "write_file", "args": {"Path": path, "Content": text}}}
    else:
        payload = dict(extra, tool_name="Write", tool_input={"file_path": path, "content": text})
decision = "allow"
for group in groups:
    for hook in group["hooks"]:
        out = subprocess.run([hook["command"]], input=json.dumps(payload), capture_output=True, text=True).stdout
        if os.environ.get("STUB_ALLOW_HOOK") == "1":
            out = json.dumps({"hookSpecificOutput": {"permissionDecision": "allow"}})
            raw_dir = os.path.join(os.path.dirname(hook["command"]), "raw")
            raw_path = sorted(glob.glob(os.path.join(raw_dir, "*.json")))[-1]
            raw = json.load(open(raw_path))
            raw["stdout"] = out
            json.dump(raw, open(raw_path, "w"))
        answer = json.loads(out)
        decision = answer.get("decision") or answer["hookSpecificOutput"]["permissionDecision"]
if os.environ.get("STUB_DISOBEY") == "1":
    decision = "allow"
if decision == "allow":
    if shell:
        subprocess.run(["bash", "-c", cmd])
    else:
        open(path, "w").write(text)
print("stub saw decision: " + decision)
`

type verifyStubRun struct {
	code     int
	output   string
	evidence string
	scratch  string
	home     string
}

// requireVerifyScript stops a test before it starts the shell entry point when
// verify_harnesses.py is absent. An older verify-harnesses.sh wrote under /tmp
// and copied sign-in files there, so a test must never start it.
func requireVerifyScript(t *testing.T) {
	t.Helper()
	p := filepath.Join("..", "..", "examples", "coding-agent-guard", "verify_harnesses.py")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("examples/coding-agent-guard/verify_harnesses.py is missing: %v", err)
	}
}

// runVerifyWithStubs runs verify-harnesses.sh with stub harnesses first on PATH.
func runVerifyWithStubs(t *testing.T, extraEnv ...string) verifyStubRun {
	t.Helper()
	requireVerifyScript(t)
	if runtime.GOOS == "windows" {
		t.Skip("verify-harnesses.sh is a POSIX shell script")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not on PATH")
	}
	tg := exampleHooksTg(t)
	root := exampleWorkspaceTempDir(t)
	bin := filepath.Join(root, "bin")
	home := filepath.Join(root, "home")
	run := verifyStubRun{evidence: filepath.Join(root, "evidence"), scratch: filepath.Join(root, "scratch"), home: home}
	for _, d := range []string{bin, run.scratch, filepath.Join(home, ".claude"), filepath.Join(home, ".codex")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	for _, n := range []string{"claude", "codex", "agy"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte(verifyStubHarness), 0o700); err != nil {
			t.Fatalf("write stub %s: %v", n, err)
		}
	}
	canary := verifyStubCanary
	for _, env := range extraEnv {
		if strings.HasPrefix(env, "STUB_SIGNIN_TEXT=") {
			canary = strings.TrimPrefix(env, "STUB_SIGNIN_TEXT=")
		}
	}
	signin, err := json.Marshal(map[string]string{"token": canary})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(home, ".claude", ".credentials.json"), filepath.Join(home, ".codex", "auth.json")} {
		if err := os.WriteFile(f, signin, 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	// A directory left by a run that was killed: the next run must remove it.
	dead := filepath.Join(run.scratch, "tg-verify.dead")
	if err := os.MkdirAll(filepath.Join(dead, "claude"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_ = os.WriteFile(filepath.Join(dead, "pid"), []byte("999999999"), 0o600)
	_ = os.WriteFile(filepath.Join(dead, "claude", ".credentials.json"), signin, 0o600)

	script := filepath.Join("..", "..", "examples", "coding-agent-guard", "verify-harnesses.sh")
	cmd := exec.Command("bash", script)
	cmd.Env = append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + home,
		"TG=" + tg,
		"TG_VERIFY_DIR=" + run.evidence,
		"TG_VERIFY_SCRATCH_BASE=" + run.scratch,
		"TG_VERIFY_TIMEOUT=60",
	}, extraEnv...)
	out, err := cmd.CombinedOutput()
	run.output = string(out)
	if exit, ok := err.(*exec.ExitError); ok {
		run.code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run verify-harnesses.sh: %v\n%s", err, out)
	}
	return run
}

// verifyEvidenceText returns every evidence file as one string.
func verifyEvidenceText(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		b.Write(raw)
		return err
	})
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	return b.String()
}

func TestVerifyHarnessesRecordsOutcomesAndKeepsNoPrivateData(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_VERIFY_REQUIRE=claude,codex,agy")
	if run.code != 0 {
		t.Fatalf("exit status %d, want 0\n%s", run.code, run.output)
	}
	left, err := os.ReadDir(run.scratch)
	if err != nil || len(left) != 0 {
		t.Errorf("scratch base must be empty after the run, has %d entries (err %v)", len(left), err)
	}
	raw, err := os.ReadFile(filepath.Join(run.evidence, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		Schema    int `json:"schema"`
		Failures  int `json:"failures"`
		Harnesses []struct {
			ID            string `json:"id"`
			Configuration string `json:"configuration"`
			Stages        []struct {
				ID       string `json:"id"`
				Decision string `json:"decision"`
				Outcome  string `json:"outcome"`
			} `json:"stages"`
		} `json:"harnesses"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	got := map[string]string{}
	for _, h := range m.Harnesses {
		for _, s := range h.Stages {
			got[h.ID+" | "+h.Configuration+" | "+s.ID] = s.Decision + " " + s.Outcome
		}
	}
	want := map[string]string{
		"claude-code | claude -p | shell_deny":                                                      "deny blocked",
		"claude-code | claude -p | shell_allow_control":                                             "allow ran",
		"claude-code | claude -p | write_tool_deny":                                                 "deny blocked",
		"claude-code | claude -p | write_tool_allow_control":                                        "allow ran",
		"claude-code | claude -p | escalation_shell":                                                "ask blocked",
		"claude-code | claude -p | escalation_write_tool":                                           "ask blocked",
		"codex-cli | codex exec, hook not trusted | untrusted_hook":                                 " ran_without_hook",
		"codex-cli | codex exec | shell_deny":                                                       "deny blocked",
		"codex-cli | codex exec | shell_allow_control":                                              "allow ran",
		"codex-cli | codex exec | write_tool_deny":                                                  "deny blocked",
		"codex-cli | codex exec | write_tool_allow_control":                                         "allow ran",
		"codex-cli | codex exec | escalation_shell":                                                 "deny blocked",
		"codex-cli | codex exec | escalation_shell_raw_ask":                                         "ask blocked",
		"antigravity-cli | agy --dangerously-skip-permissions --print | shell_deny":                 "deny blocked",
		"antigravity-cli | agy --dangerously-skip-permissions --print | escalation_shell":           "force_ask blocked",
		"antigravity-cli | agy --dangerously-skip-permissions --print | escalation_shell_plain_ask": "ask blocked",
		"antigravity-cli | agy --dangerously-skip-permissions --print | escalation_shell_as_deny":   "deny blocked",
		"antigravity-cli | agy --print | write_tool_allow_control":                                  "allow ran",
		"antigravity-cli | agy --print | escalation_shell":                                          "force_ask blocked",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("stage %q: got %q, want %q", k, got[k], v)
		}
	}
	if m.Schema != 4 || m.Failures != 0 || len(got) != 23 {
		t.Errorf("manifest: schema %d, failures %d, stages %d; want 4, 0, 23", m.Schema, m.Failures, len(got))
	}
	text := verifyEvidenceText(t, run.evidence)
	for _, private := range []string{verifyStubCanary, "123e4567-e89b-12d3-a456-426614174000", "stub.user@example.com", run.scratch, "t.jsonl"} {
		if strings.Contains(text, private) {
			t.Errorf("evidence directory contains private text %q", private)
		}
	}
	for _, kept := range []string{`"session_id"`, `"transcript_path"`, `"conversationId"`, "<uuid>", "<email>", "<scratch>"} {
		if !strings.Contains(text, kept) {
			t.Errorf("evidence directory lacks %q: dropped key names and replacement marks must be recorded", kept)
		}
	}
	if _, err := os.Stat(filepath.Join(run.evidence, "results.txt")); err != nil {
		t.Errorf("results.txt missing: %v", err)
	}
}

func TestVerifyHarnessesFailsWhenAHarnessIgnoresTheHook(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_DISOBEY=1")
	if run.code != 1 {
		t.Fatalf("exit status %d, want 1\n%s", run.code, run.output)
	}
	raw, _ := os.ReadFile(filepath.Join(run.evidence, "results.txt"))
	failed := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "FAIL") && strings.Contains(line, "shell_deny") {
			failed = true
		}
	}
	if !failed {
		t.Errorf("results.txt has no FAIL line for shell_deny:\n%s", raw)
	}
	if left, _ := os.ReadDir(run.scratch); len(left) != 0 {
		t.Errorf("scratch base must be empty after a failed run, has %d entries", len(left))
	}
}

func TestVerifyHarnessesFailsWhenAllowRecordAccompaniesProtectedWrite(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_ALLOW_HOOK=1")
	if run.code != 1 {
		t.Fatalf("exit status %d, want 1 when an allow decision accompanies a protected write\n%s", run.code, run.output)
	}
	if !strings.Contains(run.output, "FAIL") || !strings.Contains(run.output, "shell_deny") {
		t.Errorf("run did not fail the blocking stage:\n%s", run.output)
	}
}

// verifySignInKinds returns the distinct words the stub harness wrote for the
// sign-in file it found in its config home: "link" or "file".
func verifySignInKinds(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	seen := map[string]bool{}
	var kinds []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !seen[line] {
			seen[line] = true
			kinds = append(kinds, line)
		}
	}
	return kinds
}

// verifySignInMode returns the signin_mode field of the manifest of a run.
func verifySignInMode(t *testing.T, run verifyStubRun) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(run.evidence, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m struct {
		SignInMode string `json:"signin_mode"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m.SignInMode
}

// verifyHomeSignInUnchanged fails when the run changed the sign-in file in the
// home directory of the test.
func verifyHomeSignInUnchanged(t *testing.T, run verifyStubRun) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(run.home, ".claude", ".credentials.json"))
	if err != nil {
		t.Fatalf("the sign-in file in the home directory is gone: %v", err)
	}
	if want := `{"token":"` + verifyStubCanary + `"}`; string(raw) != want {
		t.Errorf("the sign-in file in the home directory changed: %q", raw)
	}
}

func TestVerifyHarnessesCopiesSignInFilesByDefault(t *testing.T) {
	kinds := filepath.Join(t.TempDir(), "kinds")
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_SIGNIN_KIND_FILE="+kinds)
	if run.code != 0 {
		t.Fatalf("exit status %d, want 0\n%s", run.code, run.output)
	}
	if got := verifySignInKinds(t, kinds); len(got) != 1 || got[0] != "file" {
		t.Errorf("the harness home held %v, want only a regular file", got)
	}
	if got := verifySignInMode(t, run); got != "copy" {
		t.Errorf("manifest signin_mode = %q, want copy", got)
	}
	verifyHomeSignInUnchanged(t, run)
}

func TestVerifyHarnessesCopiesSignInFilesWhenAsked(t *testing.T) {
	kinds := filepath.Join(t.TempDir(), "kinds")
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_SIGNIN=copy", "STUB_SIGNIN_KIND_FILE="+kinds)
	if run.code != 0 {
		t.Fatalf("exit status %d, want 0\n%s", run.code, run.output)
	}
	if got := verifySignInKinds(t, kinds); len(got) != 1 || got[0] != "file" {
		t.Errorf("the harness home held %v, want only a regular file", got)
	}
	if got := verifySignInMode(t, run); got != "copy" {
		t.Errorf("manifest signin_mode = %q, want copy", got)
	}
	if left, _ := os.ReadDir(run.scratch); len(left) != 0 {
		t.Errorf("scratch base must be empty after the run, has %d entries", len(left))
	}
	verifyHomeSignInUnchanged(t, run)
}

func TestVerifyHarnessesReportsAReplacedSignInLink(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_SIGNIN=link", "STUB_REPLACE_LINK=1")
	if run.code != 0 {
		t.Fatalf("exit status %d, want 0\n%s", run.code, run.output)
	}
	if !strings.Contains(run.output, "replaced the sign-in link") {
		t.Errorf("the run did not report the replaced link:\n%s", run.output)
	}
	if left, _ := os.ReadDir(run.scratch); len(left) != 0 {
		t.Errorf("scratch base must be empty after the run, has %d entries", len(left))
	}
	verifyHomeSignInUnchanged(t, run)
}

func TestVerifyHarnessesDefaultSignInCopyDoesNotWriteThrough(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_TRUNCATE_SIGNIN=1")
	if run.code != 0 {
		t.Fatalf("exit status %d, want 0\n%s", run.code, run.output)
	}
	verifyHomeSignInUnchanged(t, run)
}

func TestVerifyHarnessesRejectsAnUnknownSignInMode(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_SIGNIN=move")
	if run.code != 2 {
		t.Fatalf("exit status %d, want 2\n%s", run.code, run.output)
	}
	if !strings.Contains(run.output, "TG_VERIFY_SIGNIN must be link or copy") {
		t.Errorf("missing the reason line:\n%s", run.output)
	}
}

func TestVerifyHarnessesRemovesEvidenceThatHoldsSignInText(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_LEAK=1")
	if run.code != 1 {
		t.Fatalf("exit status %d, want 1\n%s", run.code, run.output)
	}
	if strings.Contains(verifyEvidenceText(t, run.evidence), verifyStubCanary) {
		t.Errorf("evidence directory still holds text from the sign-in file")
	}
	if !strings.Contains(run.output, "held text from a sign-in file") {
		t.Errorf("the run did not report the removed evidence file:\n%s", run.output)
	}
}

func TestVerifyHarnessesRejectsShortPunctuationSignInLeak(t *testing.T) {
	canary := strings.Join([]string{"CANARY", "+", "/", "=", "TOKEN"}, "")
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "STUB_LEAK=1", "STUB_SIGNIN_TEXT="+canary)
	if run.code != 1 {
		t.Fatalf("exit status %d, want 1\n%s", run.code, run.output)
	}
	if strings.Contains(verifyEvidenceText(t, run.evidence), canary) {
		t.Error("evidence retained the short punctuation credential")
	}
	if !strings.Contains(run.output, "held text from a sign-in file") {
		t.Errorf("missing credential leak failure:\n%s", run.output)
	}
}

// TestVerifyHarnessesCombinesRepeatedRuns sends every Claude Code stage more
// than once. The stub makes no tool call in its first turn, as a model
// sometimes does. With three runs, two blocked and none ran: the stage passes.
// With two runs, one blocked: that is not more than half, so the stage fails.
func TestVerifyHarnessesCombinesRepeatedRuns(t *testing.T) {
	for _, tc := range []struct {
		repeat     string
		runs       int
		wantCode   int
		wantResult string
		wantBlock  int
	}{
		{"3", 3, 0, "PASS", 2},
		{"2", 2, 1, "FAIL", 1},
	} {
		counter := filepath.Join(t.TempDir(), "turns")
		run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_REPEAT="+tc.repeat,
			"STUB_COUNT_FILE="+counter, "STUB_SILENT_TURN=1")
		if run.code != tc.wantCode {
			t.Fatalf("repeat %s: exit status %d, want %d\n%s", tc.repeat, run.code, tc.wantCode, run.output)
		}
		raw, err := os.ReadFile(filepath.Join(run.evidence, "manifest.json"))
		if err != nil {
			t.Fatalf("repeat %s: read manifest: %v", tc.repeat, err)
		}
		var m struct {
			Repeat    int `json:"repeat"`
			Harnesses []struct {
				Stages []struct {
					ID       string         `json:"id"`
					Runs     int            `json:"runs"`
					Outcomes map[string]int `json:"outcomes"`
					Outcome  string         `json:"outcome"`
					Result   string         `json:"result"`
				} `json:"stages"`
			} `json:"harnesses"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("repeat %s: parse manifest: %v", tc.repeat, err)
		}
		if m.Repeat != tc.runs || len(m.Harnesses) != 1 || len(m.Harnesses[0].Stages) != 6 {
			t.Fatalf("repeat %s: manifest repeat %d, harnesses %d; want %d, 1 harness with 6 stages", tc.repeat, m.Repeat, len(m.Harnesses), tc.runs)
		}
		for i, s := range m.Harnesses[0].Stages {
			total := 0
			for _, n := range s.Outcomes {
				total += n
			}
			if s.Runs != tc.runs || total != tc.runs {
				t.Errorf("repeat %s: stage %s has runs %d and %d counted outcomes, want %d", tc.repeat, s.ID, s.Runs, total, tc.runs)
			}
			if i == 0 {
				if s.ID != "shell_deny" || s.Outcome != "mixed" || s.Result != tc.wantResult ||
					s.Outcomes["blocked"] != tc.wantBlock || s.Outcomes["not_measured"] != 1 {
					t.Errorf("repeat %s: first stage is %+v; want shell_deny, mixed, %s, blocked %d, not_measured 1", tc.repeat, s, tc.wantResult, tc.wantBlock)
				}
				continue
			}
			if len(s.Outcomes) != 1 || s.Outcome == "mixed" || s.Result == "FAIL" {
				t.Errorf("repeat %s: stage %s must have one outcome in every run, got %+v", tc.repeat, s.ID, s)
			}
		}
	}
}

func TestVerifyHarnessesRejectsABadRepeatValue(t *testing.T) {
	for _, bad := range []string{"0", "10", "two"} {
		run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_REPEAT="+bad)
		if run.code != 2 {
			t.Errorf("TG_VERIFY_REPEAT=%s: exit status %d, want 2\n%s", bad, run.code, run.output)
		}
		if _, err := os.Stat(filepath.Join(run.evidence, "manifest.json")); err == nil {
			t.Errorf("TG_VERIFY_REPEAT=%s: a refused run must not write a manifest", bad)
		}
	}
}

func TestVerifyHarnessesReleaseModeRefusesThisBuild(t *testing.T) {
	// The test binary is built without -trimpath, so release mode must refuse
	// to start whether or not the working tree is clean.
	run := runVerifyWithStubs(t, "TG_VERIFY_RELEASE=1")
	if run.code != 2 {
		t.Fatalf("exit status %d, want 2\n%s", run.code, run.output)
	}
	if _, err := os.Stat(filepath.Join(run.evidence, "manifest.json")); err == nil {
		t.Errorf("a refused run must not write a manifest")
	}
}

func TestVerifyHarnessesRejectsFilterThatExcludesRequiredHarnesses(t *testing.T) {
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_REQUIRE=claude,codex,agy")
	if run.code != 2 {
		t.Fatalf("exit status %d, want 2 when TG_ONLY excludes required harnesses\n%s", run.code, run.output)
	}
	if !strings.Contains(run.output, "TG_ONLY excludes required harnesses") {
		t.Errorf("preflight did not explain the conflict:\n%s", run.output)
	}
}

func TestVerifyHarnessesFailsWhenARequiredHarnessIsMissing(t *testing.T) {
	requireVerifyScript(t)
	// PATH holds three links and nothing else, so a real harness installed on
	// this machine cannot be found and no paid call can happen.
	tools := t.TempDir()
	for _, n := range []string{"python3", "bash", "dirname"} {
		real, err := exec.LookPath(n)
		if err != nil {
			t.Skipf("%s is not on PATH", n)
		}
		if err := os.Symlink(real, filepath.Join(tools, n)); err != nil {
			t.Fatalf("link %s: %v", n, err)
		}
	}
	run := runVerifyWithStubs(t, "TG_ONLY=claude", "TG_VERIFY_REQUIRE=claude", "PATH="+tools)
	if run.code != 1 {
		t.Fatalf("exit status %d, want 1 when a required harness is not on PATH\n%s", run.code, run.output)
	}
	if !strings.Contains(run.output, "is required (TG_VERIFY_REQUIRE) and is not on PATH") {
		t.Errorf("the run did not name the missing harness:\n%s", run.output)
	}
}
