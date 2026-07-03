//go:build integration

// Integration tests for the -protect-paths / -protect-self flags on tg-proxy.
// Launches a dedicated proxy instance (separate from the shared TestMain proxy)
// with protect paths configured, posts tool calls, and asserts:
//   - HTTP 403 + decision=denied for writes to protected paths
//   - HTTP 200 + decision=allowed for reads of those same paths
//   - Audit chain remains intact (tg verify semantics) after the deny

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
)

// minimalPolicy is a benign policy that lets the proxy pass /readyz
// (requires at least one policy when -fail-closed=true).
const protectTestPolicy = `policy_id: pol-protect-test
name: protect-test-allow-all
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [read]
  tool_groups: [filesystem]
rules:
  - rule_id: flag-reads
    conditions:
      field: tool_name
      operator: eq
      value: read
    effect: flag
    citation: {document_id: d, excerpt: "flag reads for observation"}
`

// startProtectProxy launches a fresh tg-proxy instance with the supplied
// protect flags, a minimal policy, and its own audit log. It returns the
// base URL and a teardown function to kill the process.
func startProtectProxy(t *testing.T, extraArgs ...string) (baseURL string, teardown func()) {
	t.Helper()
	tmp := t.TempDir()
	polDir := filepath.Join(tmp, "policies")
	auditLog := filepath.Join(tmp, "audit.jsonl")
	if err := os.MkdirAll(polDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	if err := os.WriteFile(filepath.Join(polDir, "base.yaml"), []byte(protectTestPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "http://" + addr

	args := []string{
		"-listen", addr,
		"-policy-dir", polDir,
		"-audit-log", auditLog,
	}
	args = append(args, extraArgs...)

	cmd := exec.Command(proxyBin, args...)
	cmd.Stdout = os.Stderr // pass through for debugging on failure
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start protect proxy: %v", err)
	}

	if err := waitReady(url+"/readyz", 5*time.Second); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		t.Fatalf("protect proxy did not become ready: %v", err)
	}

	return url, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	}
}

// postEvaluate sends an /evaluate POST and returns the HTTP status plus the
// decoded body as a map.
func postEvaluateRaw(t *testing.T, baseURL string, env map[string]any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(env); err != nil {
		t.Fatalf("encode: %v", err)
	}
	resp, err := http.Post(baseURL+"/evaluate", "application/json", &buf)
	if err != nil {
		t.Fatalf("POST /evaluate: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	return resp.StatusCode, decoded
}

// ── protect tests ──────────────────────────────────────────────────────────

// TestProtect_WriteToProtectedPath_Returns403 verifies that a write-capable
// tool targeting a protected prefix receives HTTP 403 + decision=denied,
// and the audit chain remains intact afterward.
func TestProtect_WriteToProtectedPath_Returns403(t *testing.T) {
	tmp := t.TempDir()
	protectedDir := filepath.Join(tmp, "policies") // arbitrary protected prefix
	auditLog := filepath.Join(tmp, "audit.jsonl")
	polDir := filepath.Join(tmp, "pdir")
	if err := os.MkdirAll(polDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(polDir, "base.yaml"), []byte(protectTestPolicy), 0o644); err != nil {
		t.Fatal(err)
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	baseURL := "http://" + addr

	cmd := exec.Command(proxyBin,
		"-listen", addr,
		"-policy-dir", polDir,
		"-audit-log", auditLog,
		"-protect-paths", protectedDir,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	}()
	if err := waitReady(baseURL+"/readyz", 5*time.Second); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	// POST a write tool call targeting the protected path.
	targetFile := filepath.Join(protectedDir, "evil.yaml")
	env := map[string]any{
		"envelope_id": "env-protect-write-1",
		"agent_id":    "test-agent",
		"session_id":  "sess-1",
		"org_id":      "org-1",
		"tool_name":   "write",
		"tool_group":  "filesystem",
		"parameters":  map[string]any{"file_path": targetFile},
	}
	status, body := postEvaluateRaw(t, baseURL, env)

	// Assert HTTP 403.
	if status != http.StatusForbidden {
		t.Errorf("expected HTTP 403 for write to protected path, got %d; body=%v", status, body)
	}
	// Assert decision=denied in response body.
	if decision, _ := body["decision"].(string); decision != "denied" {
		t.Errorf("expected decision=denied in body, got %q; body=%v", decision, body)
	}

	// Give the proxy a moment to flush the audit log.
	time.Sleep(30 * time.Millisecond)

	// ── Assert audit chain intact ──────────────────────────────────────────
	f, err := os.Open(auditLog)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if !report.Intact {
		t.Errorf("audit chain broken after protect-path deny: failure_reason=%q at line %d",
			report.FailureReason, report.FirstFailureAt)
	}
	if report.Records < 1 {
		t.Errorf("expected at least 1 audit record (the boundary deny), got %d", report.Records)
	}

	// ── Inspect the audit log content ─────────────────────────────────────
	// The audit log should contain a trace with decision=denied for env-protect-write-1.
	f2, err := os.Open(auditLog)
	if err != nil {
		t.Fatalf("re-open audit log: %v", err)
	}
	defer f2.Close()
	raw, _ := io.ReadAll(f2)
	if !bytes.Contains(raw, []byte(`"denied"`)) {
		t.Errorf("audit log should contain a denied trace; log content:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`env-protect-write-1`)) {
		t.Errorf("audit log should reference envelope_id env-protect-write-1; log content:\n%s", raw)
	}
}

// TestProtect_ReadOfProtectedPath_Returns200 verifies that a read-only tool
// targeting a protected path is NOT denied (protect fires only on write tools).
func TestProtect_ReadOfProtectedPath_Returns200(t *testing.T) {
	tmp := t.TempDir()
	protectedDir := filepath.Join(tmp, "policies")

	baseURL, teardown := startProtectProxy(t, "-protect-paths", protectedDir)
	defer teardown()

	targetFile := filepath.Join(protectedDir, "policy.yaml")
	env := map[string]any{
		"envelope_id": "env-protect-read-1",
		"agent_id":    "test-agent",
		"session_id":  "sess-1",
		"org_id":      "org-1",
		"tool_name":   "read", // read is NOT a write tool
		"tool_group":  "filesystem",
		"parameters":  map[string]any{"file_path": targetFile},
	}
	status, body := postEvaluateRaw(t, baseURL, env)

	// Must be 200 (not 403) — reading a protected path is allowed.
	if status != http.StatusOK {
		t.Errorf("expected HTTP 200 for read of protected path, got %d; body=%v", status, body)
	}
	if decision, _ := body["decision"].(string); decision == "denied" {
		t.Errorf("read of protected path must NOT be denied, got decision=%q", decision)
	}
}

// TestProtect_ShellCommandToProtectedPath_Returns403 verifies that a bash
// command writing to a protected path is caught by the shell best-effort
// heuristic and denied.
func TestProtect_ShellCommandToProtectedPath_Returns403(t *testing.T) {
	tmp := t.TempDir()
	protectedDir := filepath.Join(tmp, "policies")

	baseURL, teardown := startProtectProxy(t, "-protect-paths", protectedDir)
	defer teardown()

	targetFile := filepath.Join(protectedDir, "pwned.yaml")
	cmd := fmt.Sprintf("echo evil > %s", targetFile)

	env := map[string]any{
		"envelope_id": "env-protect-shell-1",
		"agent_id":    "test-agent",
		"session_id":  "sess-1",
		"org_id":      "org-1",
		"tool_name":   "bash",
		"tool_group":  "shell",
		"parameters":  map[string]any{"command": cmd},
	}
	status, body := postEvaluateRaw(t, baseURL, env)

	if status != http.StatusForbidden {
		t.Errorf("expected HTTP 403 for shell write to protected path, got %d; body=%v", status, body)
	}
	if decision, _ := body["decision"].(string); decision != "denied" {
		t.Errorf("expected decision=denied for shell write, got %q", decision)
	}
	// Reason should mention best-effort.
	reason, _ := body["decision_reason"].(string)
	if !strings.Contains(reason, "-protect-paths") {
		t.Errorf("reason should mention -protect-paths, got %q", reason)
	}
}

// TestProtect_AuditChainIntactAfterMultipleDenies asserts that multiple
// protect-path deny events all enter the audit chain and leave it intact.
func TestProtect_AuditChainIntactAfterMultipleDenies(t *testing.T) {
	tmp := t.TempDir()
	protectedDir := filepath.Join(tmp, "secret-policies")
	auditLog := filepath.Join(tmp, "audit.jsonl")
	polDir := filepath.Join(tmp, "pdir")
	if err := os.MkdirAll(polDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(polDir, "base.yaml"), []byte(protectTestPolicy), 0o644); err != nil {
		t.Fatal(err)
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	baseURL := "http://" + addr

	cmd := exec.Command(proxyBin,
		"-listen", addr,
		"-policy-dir", polDir,
		"-audit-log", auditLog,
		"-protect-paths", protectedDir,
		"-audit-sync-mode", "every",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	}()
	if err := waitReady(baseURL+"/readyz", 5*time.Second); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	// Fire three protect-path denies.
	for i := 0; i < 3; i++ {
		env := map[string]any{
			"envelope_id": fmt.Sprintf("env-multi-protect-%d", i),
			"agent_id":    "test-agent",
			"session_id":  "sess-1",
			"org_id":      "org-1",
			"tool_name":   "write",
			"tool_group":  "filesystem",
			"parameters":  map[string]any{"file_path": filepath.Join(protectedDir, fmt.Sprintf("file%d.yaml", i))},
		}
		if status, _ := postEvaluateRaw(t, baseURL, env); status != http.StatusForbidden {
			t.Errorf("call %d: expected 403, got %d", i, status)
		}
	}
	time.Sleep(30 * time.Millisecond)

	f, err := os.Open(auditLog)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		t.Fatalf("VerifyChainFromReader: %v", err)
	}
	if !report.Intact {
		t.Errorf("audit chain broken after %d protect denies: %s", 3, report.FailureReason)
	}
	if report.Records < 3 {
		t.Errorf("expected at least 3 audit records, got %d", report.Records)
	}
}
