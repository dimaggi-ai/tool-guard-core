//go:build integration

// End-to-end proof that -velocity-track closes the amount-fragmentation
// bypass: many small refunds under a per-call cap, denied once their
// rolling 1h sum crosses the ceiling. Launches its own proxy instance
// (the shared TestMain proxy runs without velocity) reusing the binary
// TestMain already built.
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
	"syscall"
	"testing"
	"time"
)

const velocityPolicy = `policy_id: pol-velocity
name: refund-1h-velocity-cap
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
rules:
  - rule_id: velocity-1h
    name: 1h rolling refund cap
    conditions: {field: context.verified.agent_velocity.monetary_sum_1h, operator: gt, value: 5000}
    effect: deny
    citation: {document_id: SOP-REFUND, excerpt: "cumulative refunds may not exceed $5,000/hour"}
`

// startVelocityProxy launches a dedicated proxy with -velocity-track and
// returns its base URL plus a cleanup func.
func startVelocityProxy(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	pdir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "velocity.yaml"), []byte(velocityPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(proxyBin,
		"-listen", addr,
		"-policy-dir", pdir,
		"-audit-log", filepath.Join(dir, "audit.jsonl"),
		"-velocity-track",
		"-velocity-key-by", "agent_id",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	url := "http://" + addr
	if err := waitReady(url+"/readyz", 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("velocity proxy not ready: %v", err)
	}
	return url, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
	}
}

func refundEnvelope(agent string, amount float64) map[string]any {
	return map[string]any{
		"agent_id":   agent,
		"tool_name":  "issue_refund",
		"tool_group": "monetary_outflow",
		"parameters": map[string]any{"amount": amount},
	}
}

func postTo(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	resp, err := http.Post(url+"/evaluate", "application/json", &buf)
	if err != nil {
		t.Fatalf("POST /evaluate: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestVelocity_BlocksAmountFragmentation(t *testing.T) {
	url, stop := startVelocityProxy(t)
	defer stop()

	// 12 × $500 refunds by the same agent. Cap is $5,000/1h. The rolling
	// sum INCLUDING the prospective call crosses $5,000 on the 11th, so
	// the first 10 allow ($5,000 total) and the rest deny.
	allowed, denied := 0, 0
	for i := 1; i <= 12; i++ {
		_, out := postTo(t, url, refundEnvelope("frag-agent", 500))
		switch out["decision"] {
		case "allowed":
			allowed++
		case "denied":
			denied++
		default:
			t.Fatalf("call %d: unexpected decision %v", i, out["decision"])
		}
	}
	if allowed != 10 {
		t.Errorf("expected 10 allowed ($5,000 worth), got %d", allowed)
	}
	if denied != 2 {
		t.Errorf("expected 2 denied (11th, 12th), got %d", denied)
	}

	// A DIFFERENT agent has an independent window — one $500 refund allows.
	if _, out := postTo(t, url, refundEnvelope("other-agent", 500)); out["decision"] != "allowed" {
		t.Errorf("independent agent should be allowed, got %v", out["decision"])
	}
}

func TestVelocity_DoesNotOverrideCallerSupplied(t *testing.T) {
	url, stop := startVelocityProxy(t)
	defer stop()

	// Caller supplies its own (authoritative) agent_velocity already over
	// the cap. The proxy must NOT overwrite it, so a single $1 refund is
	// denied on the caller's figure — proving the ledger stays in charge.
	env := refundEnvelope("ledger-agent", 1)
	env["context"] = map[string]any{
		"verified": map[string]any{
			"agent_velocity": map[string]any{"monetary_sum_1h": 9000},
		},
	}
	if _, out := postTo(t, url, env); out["decision"] != "denied" {
		t.Errorf("caller-supplied velocity should be honoured (deny), got %v", out["decision"])
	}
}
