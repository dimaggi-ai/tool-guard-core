package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hookDecision decodes the JSON written to stdout by runHook and returns
// the permissionDecision field (deny | ask | allow).
func hookDecision(t *testing.T, output string) string {
	t.Helper()
	var out hookOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &out); err != nil {
		t.Fatalf("hook stdout not valid JSON: %v\n%s", err, output)
	}
	return out.HookSpecificOutput.PermissionDecision
}

// hookDecisionReason returns both the decision and the reason string.
func hookDecisionReason(t *testing.T, output string) (decision, reason string) {
	t.Helper()
	var out hookOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &out); err != nil {
		t.Fatalf("hook stdout not valid JSON: %v\n%s", err, output)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

// runHookStr runs runHook with the given args and stdinStr, returns stdout.
func runHookStr(t *testing.T, stdinStr string, args ...string) (stdout string, code int) {
	t.Helper()
	var buf bytes.Buffer
	code = runHook(args, strings.NewReader(stdinStr), &buf)
	return buf.String(), code
}

// ── policy fixtures ────────────────────────────────────────────────────────

const hookDenyPolicy = `policy_id: hook-deny-test
name: hook-deny-test
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash]
  tool_groups: [shell]
rules:
  - rule_id: deny-rm
    conditions:
      field: parameters.command
      operator: regex
      value: 'rm'
    effect: deny
    citation: {document_id: d, excerpt: "no rm"}
`

const hookAskPolicy = `policy_id: hook-ask-test
name: hook-ask-test
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash]
  tool_groups: [shell]
rules:
  - rule_id: escalate-git
    conditions:
      field: parameters.command
      operator: regex
      value: 'git'
    effect: escalate
    effect_config:
      severity: medium
      escalate_to: human
      timeout_minutes: 15
    citation: {document_id: d, excerpt: "git needs review"}
`

const hookAllowPolicy = `policy_id: hook-allow-test
name: hook-allow-test
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash]
  tool_groups: [shell]
rules:
  - rule_id: allow-grep
    conditions:
      field: parameters.command
      operator: regex
      value: 'NEVER_MATCHES_ANYTHING_12345'
    effect: deny
    citation: {document_id: d, excerpt: "unreachable"}
`

func writeHookPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

// ── B1: deny / ask / allow mapping from policy ────────────────────────────

func TestHook_PolicyDeny(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	stdin := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/x"}}`
	out, code := runHookStr(t, stdin, "-policy", pol)
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("expected deny, got %q; output=%s", d, out)
	}
}

func TestHook_PolicyAsk(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	stdin := `{"tool_name":"bash","tool_input":{"command":"git push origin main"}}`
	out, code := runHookStr(t, stdin, "-policy", pol)
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "ask" {
		t.Errorf("expected ask (escalated), got %q; output=%s", d, out)
	}
}

func TestHook_PolicyAllow(t *testing.T) {
	pol := writeHookPolicy(t, hookAllowPolicy)
	stdin := `{"tool_name":"bash","tool_input":{"command":"go test ./..."}}`
	out, code := runHookStr(t, stdin, "-policy", pol)
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("expected allow, got %q; output=%s", d, out)
	}
}

// TestHook_ShadowMode_ObservesDoesNotEnforce guards against a bug an
// adversarial review caught: evalHook used to switch on result.Decision
// (what WOULD happen) instead of result.ActionTaken (what actually
// happens). A shadow-mode policy sets Decision=denied but
// ActionTaken=allowed_shadow — branching on Decision made `tg hook -mode
// shadow` silently enforce every policy, since the calling agent (Claude
// Code / Codex / etc.) actually blocks the tool call on a "deny"
// permissionDecision regardless of what mode label the engine used
// internally. Shadow mode exists specifically to observe without ever
// blocking; this proves it actually does that at the hook's own JSON
// output, not just inside the engine.
func TestHook_ShadowMode_ObservesDoesNotEnforce(t *testing.T) {
	shadowDenyPolicy := strings.Replace(hookDenyPolicy, "mode: enforcement", "mode: shadow", 1)
	pol := writeHookPolicy(t, shadowDenyPolicy)
	stdin := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/x"}}`
	out, code := runHookStr(t, stdin, "-policy", pol, "-mode", "shadow")
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("shadow mode must never block — expected allow (near-miss observed, not enforced), got %q; output=%s", d, out)
	}
}

// ── B2: fail-open on malformed stdin ──────────────────────────────────────

func TestHook_MalformedStdin_FailOpen(t *testing.T) {
	// Without -fail-closed, a broken stdin must produce allow.
	out, code := runHookStr(t, "this is not json at all")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("malformed stdin must fail OPEN (allow) by default, got %q", d)
	}
}

func TestHook_MalformedStdin_FailClosed(t *testing.T) {
	// With -fail-closed, a broken stdin must produce deny.
	out, code := runHookStr(t, "not-json", "-fail-closed")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("malformed stdin with -fail-closed must deny, got %q", d)
	}
}

// ── B3: -fail-closed-tools: denies listed tool on error, allows others ────

func TestHook_FailClosedTools_ListedTool(t *testing.T) {
	// No policy → internal error. bash is in the fail-closed list → deny.
	stdin := `{"tool_name":"bash","tool_input":{"command":"ls"}}`
	out, code := runHookStr(t, stdin, "-fail-closed-tools", "bash")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("-fail-closed-tools bash: bash tool on internal error must deny, got %q", d)
	}
}

func TestHook_FailClosedTools_UnlistedTool(t *testing.T) {
	// No policy → internal error. "read" is NOT in the fail-closed list → allow.
	stdin := `{"tool_name":"read","tool_input":{"file_path":"/tmp/x"}}`
	out, code := runHookStr(t, stdin, "-fail-closed-tools", "bash,write,edit")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("-fail-closed-tools bash,write,edit: unlisted tool 'read' on internal error must allow, got %q", d)
	}
}

func TestHook_FailClosedTools_CaseInsensitive(t *testing.T) {
	// -fail-closed-tools matching is case-insensitive.
	// The hook lowercases tool_name from the JSON before matching.
	stdin := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
	out, code := runHookStr(t, stdin, "-fail-closed-tools", "BASH")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("fail-closed-tools matching should be case-insensitive; Bash vs BASH got %q", d)
	}
}

// ── B4: -protect-paths deny fires before policy eval ──────────────────────

func TestHook_ProtectPaths_DenyBeforePolicy(t *testing.T) {
	// No policy needed — protect fires unconditionally before policy.
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/guarded/policy.yaml"}}`
	out, code := runHookStr(t, stdin, "-protect-paths", "/guarded")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	d, reason := hookDecisionReason(t, out)
	if d != "deny" {
		t.Errorf("-protect-paths: expected deny, got %q", d)
	}
	if !strings.Contains(reason, "-protect-paths") {
		t.Errorf("reason should reference -protect-paths, got %q", reason)
	}
}

func TestHook_RepeatableProtectPathPreservesComma(t *testing.T) {
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/guarded,exact/policy.yaml"}}`
	out, code := runHookStr(t, stdin,
		"-protect-path", "/other",
		"-protect-path", "/guarded,exact",
	)
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("repeatable -protect-path must preserve and deny a comma-containing path, got %q", d)
	}
}

func TestHook_ProtectPaths_AllowUnprotected(t *testing.T) {
	// Writing to an unprotected path with -protect-paths set and no policy
	// → no protect violation → falls through to no-policy → fail-open → allow.
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/tmp/safe.txt"}}`
	out, code := runHookStr(t, stdin, "-protect-paths", "/guarded")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("unprotected path with no policy must allow (fail-open), got %q", d)
	}
}

func TestHook_ProtectPaths_ReadNotDenied(t *testing.T) {
	// Reading a protected path with -protect-paths must NOT fire
	// (ViolatesProtectedPaths excludes read-only tools).
	// With no policy → fail-open → allow.
	stdin := `{"tool_name":"read","tool_input":{"file_path":"/guarded/policy.yaml"}}`
	out, code := runHookStr(t, stdin, "-protect-paths", "/guarded")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("read of protected path must not be denied by -protect-paths, got %q", d)
	}
}

// ── B5: -protect-self resolves the policy dir as a protected prefix ────────

func TestHook_ProtectSelf_DeniesWriteToOwnPolicyDir(t *testing.T) {
	// Write a real policy so the hook can load it (no-policy → fail-open
	// would bypass the protect check, but protect fires BEFORE no-policy check).
	polDir := t.TempDir()
	polPath := filepath.Join(polDir, "policy.yaml")
	if err := os.WriteFile(polPath, []byte(hookAllowPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	// Now try to write a file inside the policy directory. ToSlash: target
	// is a real OS path (polDir is t.TempDir()) - on Windows that's
	// backslash-separated, and embedding it raw into the JSON string
	// literal below would produce invalid JSON (a literal "\e" from
	// "...\evil.yaml" is not a valid JSON escape). Forward slashes need no
	// escaping and Go's Windows path functions accept "/" as an input
	// separator too, so this doesn't change what path is under test.
	target := filepath.ToSlash(filepath.Join(polDir, "evil.yaml"))
	stdin := `{"tool_name":"write","tool_input":{"file_path":"` + target + `"}}`
	out, code := runHookStr(t, stdin, "-policy-dir", polDir, "-protect-self")
	if code != 0 {
		t.Errorf("exit must be 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("-protect-self must deny writes inside policy-dir, got %q (target=%s)", d, target)
	}
}

// ── B6: hookEventName is always PreToolUse ────────────────────────────────

func TestHook_EventName(t *testing.T) {
	// The hook must always emit hookEventName: PreToolUse regardless of
	// the decision outcome.
	cases := []struct {
		name  string
		stdin string
		args  []string
	}{
		{"allow (no policy)", `{"tool_name":"read","tool_input":{}}`, nil},
		{"deny (protect-paths)", `{"tool_name":"write","tool_input":{"file_path":"/guarded/x"}}`, []string{"-protect-paths", "/guarded"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			runHook(tc.args, strings.NewReader(tc.stdin), &buf)
			var out hookOutput
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
				t.Fatalf("hook stdout not valid JSON: %v\n%s", err, buf.String())
			}
			if got := out.HookSpecificOutput.HookEventName; got != "PreToolUse" {
				t.Errorf("hookEventName = %q, want PreToolUse", got)
			}
		})
	}
}

// ── B7: always exits 0 ────────────────────────────────────────────────────

func TestHook_AlwaysExitsZero(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		args  []string
	}{
		{"empty stdin", "", nil},
		{"malformed json", "not-json", nil},
		{"fail-closed malformed", "not-json", []string{"-fail-closed"}},
		{"protect deny", `{"tool_name":"write","tool_input":{"file_path":"/guarded/x"}}`, []string{"-protect-paths", "/guarded"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, code := runHookStr(t, tc.stdin, tc.args...)
			if code != 0 {
				t.Errorf("runHook must return 0 always, got %d", code)
			}
		})
	}
}

func TestHookToolGroup_CapabilityMappings(t *testing.T) {
	tests := map[string]string{
		"write":        "filesystem_writes",
		"edit":         "filesystem_writes",
		"notebookedit": "filesystem_writes",
		"apply_patch":  "filesystem_writes",
		"multiedit":    "filesystem_writes",
		"create":       "filesystem_writes",
		"read":         "filesystem",
		"http":         "network_egress",
		"fetch":        "network_egress",
		"webfetch":     "network_egress",
		"bash":         "shell",
	}
	for tool, want := range tests {
		if got := hookToolGroup(tool); got != want {
			t.Errorf("hookToolGroup(%q) = %q, want %q", tool, got, want)
		}
	}
}

// ── B8: -unknown-tools-deny ───────────────────────────────────────────────
// tg-proxy has had -unknown-tools-deny since before 0.5.0; tg hook — the
// coding-agent enforcement point most deployments actually run — did not.
// A new tool the agent starts calling that no policy's tool_names declares
// (and whose tool_group, if any, also isn't scoped) previously matched no
// policy and fell through to the default allow, completely ungoverned.

func TestHook_UnknownToolsDeny_DeniesUndeclaredTool(t *testing.T) {
	// Scoped to tool_names:[bash] + tool_groups:[shell] only — "write", a
	// filesystem_writes-group tool, matches neither dimension, so a normal eval
	// matches no policy at all (default allow) whether or not the flag is
	// set. -unknown-tools-deny must override that default and deny.
	pol := writeHookPolicy(t, hookAllowPolicy)
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/tmp/new-file.txt","content":"x"}}`
	out, code := runHookStr(t, stdin, "-policy", pol, "-unknown-tools-deny")
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	decision, reason := hookDecisionReason(t, out)
	if decision != "deny" {
		t.Fatalf("expected deny for an undeclared tool_name, got %q; output=%s", decision, out)
	}
	if !strings.Contains(reason, "write") || !strings.Contains(reason, "unknown-tools-deny") {
		t.Errorf("reason should name the tool and the flag, got %q", reason)
	}
}

func TestHook_UnknownToolsDeny_OffByDefault(t *testing.T) {
	// Same undeclared tool, same policy, but WITHOUT the flag: must fall
	// through to the engine's default (no policy matched -> allow) exactly
	// as before this change — proves the flag is opt-in, not a silent
	// behavior change for existing deployments.
	pol := writeHookPolicy(t, hookAllowPolicy)
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/tmp/new-file.txt","content":"x"}}`
	out, code := runHookStr(t, stdin, "-policy", pol)
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("without -unknown-tools-deny, undeclared tool should fall through to default allow, got %q; output=%s", d, out)
	}
}

func TestHook_UnknownToolsDeny_DeclaredToolStillEvaluatesNormally(t *testing.T) {
	// bash IS declared in tool_names, so -unknown-tools-deny must NOT block
	// it — it should proceed to the engine, which allows here (no rule
	// matches "go test ./...").
	pol := writeHookPolicy(t, hookAllowPolicy)
	stdin := `{"tool_name":"bash","tool_input":{"command":"go test ./..."}}`
	out, code := runHookStr(t, stdin, "-policy", pol, "-unknown-tools-deny")
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "allow" {
		t.Errorf("declared tool_name should evaluate normally (allow here), got %q; output=%s", d, out)
	}
}

func TestHook_UnknownToolsDeny_ShadowPolicyDoesNotCount(t *testing.T) {
	// A tool_names declaration in a SHADOW-mode policy must not satisfy
	// -unknown-tools-deny — nothing is actually enforcing on it yet, so
	// treating it as "known" would let a real gap through silently. Mirrors
	// engine.ToolNameKnown's documented shadow exclusion.
	shadowPolicy := `policy_id: hook-shadow-test
name: hook-shadow-test
version: 1
status: approved
mode: shadow
scope:
  tool_names: [notify_slack]
rules:
  - rule_id: never-fires
    conditions:
      field: parameters.x
      operator: eq
      value: NEVER_MATCHES
    effect: deny
    citation: {document_id: d, excerpt: "unreachable"}
`
	pol := writeHookPolicy(t, shadowPolicy)
	stdin := `{"tool_name":"notify_slack","tool_input":{"message":"hi"}}`
	// Hook's own runtime -mode is left at the default (enforcement) —
	// deliberately, so this test isolates ONE claim: a shadow-mode POLICY's
	// tool_names declaration doesn't satisfy ToolNameKnown. The check runs
	// before the engine either way, so the hook's runtime mode floor is not
	// what's under test here.
	out, code := runHookStr(t, stdin, "-policy", pol, "-unknown-tools-deny")
	if code != 0 {
		t.Errorf("hook must always exit 0, got %d", code)
	}
	if d := hookDecision(t, out); d != "deny" {
		t.Errorf("a shadow-only tool_names declaration must not count as 'known'; expected deny, got %q; output=%s", d, out)
	}
}
