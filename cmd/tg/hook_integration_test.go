//go:build integration

// Integration tests for `tg hook`. TestMain in integration_test.go builds
// the tg binary; these tests drive it over real subprocess invocations and
// assert the documented hook JSON contract.
//
// Run with: go test -tags=integration ./cmd/tg/...

package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hookResultJSON is the wire shape emitted by `tg hook` on stdout.
type hookResultJSON struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// runHookBin drives tg hook, piping stdinPayload to the process stdin.
// Returns the parsed hookResultJSON, raw stdout, and exit code.
// Uses tgBinary defined by TestMain in integration_test.go.
func runHookBin(t *testing.T, stdinPayload string, args ...string) (hookResultJSON, string, int) {
	t.Helper()
	fullArgs := append([]string{"hook"}, args...)
	cmd := exec.Command(tgBinary, fullArgs...)
	cmd.Stdin = strings.NewReader(stdinPayload)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	code := 0
	if err := cmd.Run(); err != nil {
		// The hook must always exit 0; if it doesn't the test will catch it.
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	stdout := outBuf.String()
	var res hookResultJSON
	_ = json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &res)
	return res, stdout, code
}

// ── hook integration policies ──────────────────────────────────────────────

const hookIntDenyPolicy = `policy_id: hook-int-deny
name: hook-int-deny
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [bash]
  tool_groups: [shell]
rules:
  - rule_id: deny-dangerous
    conditions:
      field: parameters.command
      operator: regex
      value: 'rm\s+-rf'
    effect: deny
    citation: {document_id: d, excerpt: "no recursive rm"}
`

// TestHookIntegration_DangerousCommandDenied pipes a destructive bash
// command through the real tg binary and asserts the deny decision.
func TestHookIntegration_DangerousCommandDenied(t *testing.T) {
	dir := t.TempDir()
	pol := writeFile(t, dir, "policy.yaml", hookIntDenyPolicy)

	stdin := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/scratch"}}`
	res, stdout, code := runHookBin(t, stdin, "-policy", pol)

	if code != 0 {
		t.Errorf("tg hook must always exit 0; got %d", code)
	}
	if res.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse; stdout=%s",
			res.HookSpecificOutput.HookEventName, stdout)
	}
	if res.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny; stdout=%s",
			res.HookSpecificOutput.PermissionDecision, stdout)
	}
}

// TestHookIntegration_ProtectPaths_DenyBeforePolicy exercises the
// -protect-paths flag end-to-end: writing to a protected prefix is denied
// unconditionally even when the loaded policy would have allowed the call.
func TestHookIntegration_ProtectPaths_DenyBeforePolicy(t *testing.T) {
	dir := t.TempDir()
	pol := writeFile(t, dir, "policy.yaml", hookIntDenyPolicy) // deny-rm only
	_ = pol

	// Write tool targeting the protected directory is NOT covered by the
	// deny-rm policy, but -protect-paths should still deny it.
	protected := dir
	// ToSlash: target is a real OS path (dir is t.TempDir()) - on Windows
	// that's backslash-separated, and embedding it raw into the JSON
	// string literal below would produce invalid JSON (a literal "\e"
	// from "...\evil.yaml" is not a valid JSON escape). Forward slashes
	// need no escaping and Go's Windows path functions accept "/" as an
	// input separator too, so this doesn't change what path is under
	// test. -protect-paths below stays native (protected, not ToSlash'd)
	// since it's a real argv flag value, not JSON text.
	target := filepath.ToSlash(filepath.Join(protected, "evil.yaml"))
	stdin := `{"tool_name":"write","tool_input":{"file_path":"` + target + `"}}`

	res, stdout, code := runHookBin(t, stdin, "-policy", pol, "-protect-paths", protected)

	if code != 0 {
		t.Errorf("tg hook must always exit 0; got %d", code)
	}
	if res.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("-protect-paths: expected deny, got %q; stdout=%s",
			res.HookSpecificOutput.PermissionDecision, stdout)
	}
	reason := res.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "-protect-paths") {
		t.Errorf("reason should mention -protect-paths, got %q", reason)
	}
}

// TestHookIntegration_FailClosedTools checks the -fail-closed-tools contract:
// a write tool with no policy triggers internal-error → deny because "write"
// is in the fail-closed list.
func TestHookIntegration_FailClosedTools(t *testing.T) {
	// No -policy supplied → internal-error path.
	stdin := `{"tool_name":"write","tool_input":{"file_path":"/tmp/x"}}`
	res, stdout, code := runHookBin(t, stdin, "-fail-closed-tools", "write,edit,notebookedit")

	if code != 0 {
		t.Errorf("tg hook must always exit 0; got %d", code)
	}
	if res.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("-fail-closed-tools write: expected deny on internal error, got %q; stdout=%s",
			res.HookSpecificOutput.PermissionDecision, stdout)
	}
}

// TestHookIntegration_MalformedStdin_FailOpen verifies that garbage on
// stdin produces allow (fail-open default), not a crash or exit non-0.
func TestHookIntegration_MalformedStdin_FailOpen(t *testing.T) {
	res, stdout, code := runHookBin(t, "not valid json at all")

	if code != 0 {
		t.Errorf("tg hook must always exit 0; got %d", code)
	}
	if res.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("malformed stdin must fail OPEN (allow) by default, got %q; stdout=%s",
			res.HookSpecificOutput.PermissionDecision, stdout)
	}
}

// TestHookIntegration_ProtectSelf verifies -protect-self: the hook denies a
// write targeting the policy directory itself without needing a policy rule.
func TestHookIntegration_ProtectSelf(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "policy.yaml", hookIntDenyPolicy)

	// ToSlash: see the comment in TestHookIntegration_ProtectPaths_DenyBeforePolicy above.
	target := filepath.ToSlash(filepath.Join(dir, "injected.yaml"))
	stdin := `{"tool_name":"write","tool_input":{"file_path":"` + target + `"}}`

	// -protect-self auto-protects the -policy-dir.
	res, stdout, code := runHookBin(t, stdin, "-policy-dir", dir, "-protect-self")

	if code != 0 {
		t.Errorf("tg hook must always exit 0; got %d", code)
	}
	if res.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("-protect-self: expected deny for write into policy-dir, got %q; stdout=%s",
			res.HookSpecificOutput.PermissionDecision, stdout)
	}
}
