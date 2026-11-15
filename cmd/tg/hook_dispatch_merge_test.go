package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestHookDispatch_AllAliasCandidates(t *testing.T) {
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, tc := range []struct{ name, params, want string }{
		{"alias mutation", `{"command":"gh pr list","CommandLine":"git push"}`, "ask"},
		{"read plus unrelated", `{"command":"gh pr list","script":"pwd"}`, ""},
		{"unrelated plus read", `{"command":"pwd","script":"gh pr list"}`, ""},
		{"unrelated plus write", `{"command":"pwd","CommandLine":"git push"}`, "ask"},
		{"all reads", `{"command":"gh pr list","script":"gh issue list"}`, "allow"},
		{"numeric alias", `{"command":"gh pr list","script":17}`, "ask"},
		{"null alias", `{"command":"gh pr list","CommandLine":null}`, "ask"},
		{"missing", `{}`, "ask"},
		{"non-string", `{"command":{}}`, "ask"},
		{"policy denies alias", `{"command":"gh pr list","script":"rm -rf /tmp/x"}`, "deny"},
		{"protected alias", `{"command":"gh pr list","CommandLine":"ls > /protected/x"}`, "deny"},
		{"bad path and command", `{"command":17,"file_path":12}`, "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := runHookStr(t, `{"tool_name":"Bash","tool_input":`+tc.params+`}`, "-policy", policy, "-dispatch", "gh_read", "-protect-path", "/protected")
			if got := hookMaybeDecision(t, out); got != tc.want {
				t.Fatalf("got %q want %q: %s", got, tc.want, out)
			}
		})
	}
	params := map[string]string{"command": "gh pr list"}
	for i := 0; i < maxHookParamVariants+2; i++ {
		params["s"+strings.Repeat("_", i)+"cript"] = fmt.Sprintf("gh issue view %d", i+1)
	}
	raw, _ := json.Marshal(params)
	out, _ := runHookStr(t, `{"tool_name":"Bash","tool_input":`+string(raw)+`}`, "-policy", policy, "-dispatch", "gh_read")
	if hookDecision(t, out) != "ask" || !strings.Contains(out, "parameter-spelling limit") {
		t.Fatalf("truncated aliases must ask with explanation: %s", out)
	}
}

func TestHookDispatch_DialectsAndEscalation(t *testing.T) {
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, dialect := range []string{dialectClaude, dialectAntigravity} {
		for _, command := range []string{"gh pr list", "pwd", "git push"} {
			for _, escalation := range []string{"ask", "deny", "invalid"} {
				for _, agy := range []string{"force_ask", "ask"} {
					name := strings.Join([]string{dialect, command, escalation, agy}, "/")
					t.Run(name, func(t *testing.T) {
						out, _ := runHookStr(t, hookBashStdin(t, command), "-policy", policy, "-dispatch", "gh_read", "-dialect", dialect, "-escalate-as", escalation, "-antigravity-escalation", agy)
						fields, err := parseChildHookOutput([]byte(out))
						if err != nil {
							t.Fatal(err)
						}
						want := "allow"
						if command == "pwd" && dialect == dialectClaude {
							want = ""
						} else if command != "gh pr list" {
							want = "ask"
						}
						if want == "ask" && escalation != "ask" {
							want = "deny"
						}
						key := "permissionDecision"
						if dialect == dialectAntigravity {
							key = "decision"
							if want == "ask" {
								want = agy
							}
						}
						if fields[key] != want {
							t.Fatalf("got %q want %q: %s", fields[key], want, out)
						}
					})
				}
			}
		}
	}
	for _, params := range []string{`{"command":"pwd"}`, `{"CommandLine":"git push"}`} {
		out, _ := runHookStr(t, `{"toolCall":{"name":"Bash","args":`+params+`}}`, "-policy", policy, "-dispatch", "gh_read")
		fields, err := parseChildHookOutput([]byte(out))
		if err != nil || fields["decision"] != "force_ask" {
			t.Fatalf("auto dialect: %s (%v)", out, err)
		}
	}
}

func TestHookDispatch_ErrorsOverrideSelectiveFlags(t *testing.T) {
	for _, flags := range [][]string{{"-fail-closed-tools", "bash"}, {"-fail-closed-groups", "shell"}, {"-fail-closed=false"}} {
		for _, stdin := range []string{`{"tool_name":"Read","tool_input":{}}`, `{"tool_name":"Write","tool_input":{}}`, `{`, `{}`} {
			args := append([]string{"-dispatch", "gh_read", "-dialect", dialectAntigravity}, flags...)
			out, _ := runHookStr(t, stdin, args...)
			fields, err := parseChildHookOutput([]byte(out))
			if err != nil || fields["decision"] != "deny" {
				t.Fatalf("%v %s: %s (%v)", flags, stdin, out, err)
			}
		}
	}
}

type panicHookReader struct{}

func (panicHookReader) Read([]byte) (int, error) { panic("test reader") }

type panicOnceHookWriter struct {
	bytes.Buffer
	panicked bool
}

func (w *panicOnceHookWriter) Write(p []byte) (int, error) {
	if !w.panicked {
		w.panicked = true
		panic("test writer")
	}
	return w.Buffer.Write(p)
}

func TestHookDispatch_PanicPreservesDialect(t *testing.T) {
	var early bytes.Buffer
	runHook([]string{"-dispatch", "gh_read"}, panicHookReader{}, &early)
	fields, err := parseChildHookOutput(early.Bytes())
	if err != nil || fields["decision"] != "deny" || fields["permissionDecision"] != "deny" {
		t.Fatalf("predecode panic: %s (%v)", early.String(), err)
	}
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, dialect := range []string{dialectClaude, dialectAntigravity} {
		var out panicOnceHookWriter
		runHook([]string{"-policy", policy, "-dispatch", "gh_read", "-dialect", dialect}, strings.NewReader(hookBashStdin(t, "gh pr list")), &out)
		fields, err := parseChildHookOutput(out.Bytes())
		key := "permissionDecision"
		if dialect == dialectAntigravity {
			key = "decision"
		}
		if err != nil || fields[key] != "deny" {
			t.Fatalf("decoded panic: %s (%v)", out.String(), err)
		}
	}
}

type auditObservingWriter struct {
	bytes.Buffer
	t          *testing.T
	path       string
	wantBefore bool
}

func (w *auditObservingWriter) Write(p []byte) (int, error) {
	data, err := os.ReadFile(w.path)
	if w.wantBefore && (err != nil || len(data) == 0) {
		w.t.Fatalf("audit missing before output: %v", err)
	}
	if !w.wantBefore && !os.IsNotExist(err) {
		w.t.Fatalf("non-dispatch audit appeared before output: %v", err)
	}
	return w.Buffer.Write(p)
}

func TestHookDispatch_AuditOrderAndDialectFailure(t *testing.T) {
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, dispatch := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		out := auditObservingWriter{t: t, path: path, wantBefore: dispatch}
		args := []string{"-policy", policy, "-audit-log", path}
		if dispatch {
			args = append(args, "-dispatch", "gh_read")
		}
		runHook(args, strings.NewReader(hookBashStdin(t, "git push")), &out)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var trace domain.DecisionTrace
		if err := json.Unmarshal(bytes.TrimSpace(data), &trace); err != nil {
			t.Fatal(err)
		}
		if dispatch && (trace.Decision != domain.DecisionEscalated || trace.ActionTaken != domain.ActionEscalated) {
			t.Fatalf("dispatch audit: %+v", trace)
		}
	}
	for _, stdin := range []string{hookBashStdin(t, "gh pr list"), hookBashStdin(t, "pwd"), hookBashStdin(t, "git push"), "{"} {
		out, _ := runHookStr(t, stdin, "-policy", policy, "-dispatch", "gh_read", "-dialect", dialectAntigravity, "-audit-log", t.TempDir())
		fields, err := parseChildHookOutput([]byte(out))
		if err != nil || fields["decision"] != "deny" {
			t.Fatalf("audit failure: %s (%v)", out, err)
		}
	}
}

func TestHookSupervisor_AllDialects(t *testing.T) {
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, dialect := range []string{dialectClaude, dialectAntigravity} {
		for _, command := range []string{"gh pr list", "pwd", "git push", "rm -rf /tmp/x"} {
			args := []string{"-policy", policy, "-dispatch", "gh_read", "-dialect", dialect}
			var out, stderr bytes.Buffer
			superviseHook(strings.NewReader(hookBashStdin(t, command)), &out, &stderr, 30*time.Second, helperChild(t, "real", args...), args...)
			if dialect == dialectClaude && command == "pwd" {
				if out.Len() != 0 {
					t.Fatalf("Claude no decision: %s", &out)
				}
				continue
			}
			fields, err := parseChildHookOutput(out.Bytes())
			want, key := "allow", "permissionDecision"
			if command == "git push" || command == "pwd" {
				want = "ask"
			}
			if command == "rm -rf /tmp/x" {
				want = "deny"
			}
			if dialect == dialectAntigravity {
				key = "decision"
				if want == "ask" {
					want = "force_ask"
				}
			}
			if err != nil || fields[key] != want {
				t.Fatalf("%s/%s: %s (%v), stderr %s", dialect, command, &out, err, &stderr)
			}
		}
	}
	var out, stderr bytes.Buffer
	superviseHook(strings.NewReader("{"), &out, &stderr, time.Second, helperChild(t, "garbage"))
	fields, err := parseChildHookOutput(out.Bytes())
	if err != nil || fields["decision"] != "deny" || fields["permissionDecision"] != "deny" {
		t.Fatalf("unknown dialect denial: %s (%v)", &out, err)
	}
}

func TestHookSupervisor_DialectParserRejectsAmbiguity(t *testing.T) {
	for _, raw := range []string{
		`{"decision":""}`, `{"decision":null}`, `{"decision":1}`, `{"decision":"defer"}`,
		`{"decision":"deny","decision":"allow"}`, `{"decision":"allow","reason":"x","reason":"y"}`,
		`{"decision":"allow","extra":true}`, `{"decision":"allow"} {"decision":"deny"}`,
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse"},"decision":"allow"}`,
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"decision":"allow"}`,
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse"},"reason":"stray"}`,
	} {
		if _, err := parseChildHookOutput([]byte(raw)); err == nil {
			t.Errorf("accepted invalid output %s", raw)
		}
	}
	for _, dialect := range []string{dialectClaude, dialectAntigravity, dialectBoth} {
		for _, decision := range []string{"allow", "ask", "deny"} {
			var out bytes.Buffer
			emitHookDecisionDialect(&out, dialect, "force_ask", decision, "test")
			if _, err := parseChildHookOutput(out.Bytes()); err != nil {
				t.Errorf("%s/%s: %v", dialect, decision, err)
			}
		}
	}
}

func TestHookDispatch_ApplyPatchUnchanged(t *testing.T) {
	args := []string{"-policy-dir", filepath.Join("..", "..", "policies"), "-mode", "enforcement", "-protect-path", "/w/protected"}
	for _, target := range []string{"a.txt", "protected/a.txt"} {
		input := map[string]interface{}{"command": "*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch"}
		want, wantReason := applyPatchDecision(t, args, input, "/w")
		got, reason := applyPatchDecision(t, append(args, "-dispatch", "gh_read"), input, "/w")
		if got != want || reason != wantReason {
			t.Fatalf("dispatch changed apply_patch %s: %s/%s vs %s/%s", target, got, reason, want, wantReason)
		}
	}
}

func TestHookDispatch_ActualCLIContracts(t *testing.T) {
	bin := exampleHooksTg(t)
	policy := writeHookPolicy(t, hookDenyPolicy)
	for _, dialect := range []string{dialectClaude, dialectAntigravity} {
		for _, command := range []string{"gh pr list", "pwd", "git push"} {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			cmd := exec.CommandContext(ctx, bin, "hook", "-policy", policy, "-dispatch", "gh_read", "-dialect", dialect, "-escalate-as", "deny")
			cmd.Stdin = strings.NewReader(hookBashStdin(t, command))
			out, err := cmd.Output()
			cancel()
			if err != nil {
				t.Fatalf("actual CLI %s: %v", dialect, err)
			}
			if command == "pwd" && dialect == dialectClaude {
				if len(out) != 0 {
					t.Fatalf("CLI no-decision output: %s", out)
				}
				continue
			}
			fields, err := parseChildHookOutput(out)
			key, want := "permissionDecision", "deny"
			if dialect == dialectAntigravity {
				key = "decision"
			}
			if command == "gh pr list" {
				want = "allow"
			}
			if err != nil || fields[key] != want {
				t.Fatalf("CLI %s/%s: %s (%v)", dialect, command, out, err)
			}
		}
	}
}

var _ io.Writer = (*auditObservingWriter)(nil)
