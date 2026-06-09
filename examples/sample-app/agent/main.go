// agent is the sample agent for the tool-guard-core end-to-end demo. It
// simulates an AI agent that wants to issue a series of refunds. Before
// EACH call to the refund tool, it asks tg-proxy whether the call would
// be allowed. Only if the proxy returns "allowed" does the agent
// actually hit the refund tool.
//
// Real agent SDKs (MCP servers, LangChain callbacks, the Anthropic
// tool-use loop) do the equivalent of this in a callback — see
// docs/integration.md for the pattern.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// envelope mirrors the JSON shape pkg/domain.ActionEnvelope expects from
// tg-proxy. We hand-build it here so the sample app has zero internal
// dependencies on the Tool Guard library — that's how a real agent SDK
// in another language would talk to tg-proxy too.
type envelope struct {
	AgentID    string         `json:"agent_id"`
	SessionID  string         `json:"session_id"`
	OrgID      string         `json:"org_id"`
	ToolName   string         `json:"tool_name"`
	ToolGroup  string         `json:"tool_group"`
	Parameters map[string]any `json:"parameters"`
}

type decision struct {
	Decision       string `json:"decision"`
	ActionTaken    string `json:"action_taken"`
	DecisionReason string `json:"decision_reason"`
}

type scenario struct {
	label  string
	params map[string]any
}

func main() {
	proxyURL := flag.String("proxy", "http://localhost:19090", "tg-proxy base URL")
	toolURL := flag.String("tool", "http://localhost:18080", "refund-tool base URL")
	flag.Parse()

	scenarios := []scenario{
		{label: "small refund ($85) for a damaged item — should pass",
			params: map[string]any{"amount": 85.0, "customer_id": "CUST-001", "reason": "Damaged on arrival"}},
		{label: "large refund ($1000) without supervisor approval — should be denied by amount-cap",
			params: map[string]any{"amount": 1000.0, "customer_id": "CUST-002", "reason": "Customer asked nicely"}},
		{label: "modest refund ($85) but reason mentions $1500 — strict policy should escalate",
			params: map[string]any{"amount": 85.0, "customer_id": "CUST-003", "reason": "Partial refund for $1500 order, customer keeps item"}},
		{label: "another small refund ($120) for clean reason — should pass",
			params: map[string]any{"amount": 120.0, "customer_id": "CUST-004", "reason": "Shipping delay"}},
	}

	for i, s := range scenarios {
		fmt.Printf("\n%s scenario %d/%d %s\n", strings.Repeat("─", 8), i+1, len(scenarios), strings.Repeat("─", 8))
		fmt.Printf("  → %s\n", s.label)
		if err := runOne(*proxyURL, *toolURL, s); err != nil {
			log.Printf("agent: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}

	fmt.Println()
	fmt.Println("Done. The flow you saw:")
	fmt.Println("  1. agent asked tg-proxy whether each tool call was allowed")
	fmt.Println("  2. tg-proxy ran the policies and returned a decision")
	fmt.Println("  3. agent only hit the refund tool on \"allowed\"")
	fmt.Println("  4. every decision is in the proxy's JSONL audit log")
	fmt.Println()
	fmt.Println("Verify the audit chain offline:")
	fmt.Println("  $ ../../bin/tg verify -file decisions.jsonl")
}

func runOne(proxyURL, toolURL string, s scenario) error {
	env := envelope{
		AgentID:    "support-agent-demo",
		SessionID:  fmt.Sprintf("sess-%d", time.Now().Unix()),
		OrgID:      "demo-org",
		ToolName:   "issue_refund",
		ToolGroup:  "monetary_outflow",
		Parameters: s.params,
	}

	// Step 1: ask the proxy.
	dec, err := askProxy(proxyURL, env)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	fmt.Printf("  tg-proxy: decision=%s action=%s reason=%s\n", dec.Decision, dec.ActionTaken, dec.DecisionReason)

	// Step 2: only execute on allow / allowed_shadow. In a real agent
	// this is where the SDK either calls the tool function or short-
	// circuits with the suggested response.
	switch dec.ActionTaken {
	case "allowed", "allowed_shadow":
		resp, err := callRefundTool(toolURL, s.params)
		if err != nil {
			return fmt.Errorf("tool: %w", err)
		}
		fmt.Printf("  refund-tool: tx_id=%s amount=$%.2f\n", resp.TxID, resp.Amount)
	case "denied":
		fmt.Printf("  refund-tool: NOT CALLED (proxy denied)\n")
	case "escalated":
		fmt.Printf("  refund-tool: NOT CALLED (proxy escalated for human review)\n")
	default:
		fmt.Printf("  refund-tool: NOT CALLED (action_taken=%s)\n", dec.ActionTaken)
	}
	return nil
}

func askProxy(base string, env envelope) (*decision, error) {
	body, _ := json.Marshal(env)
	req, err := http.NewRequest(http.MethodPost, base+"/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	var d decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

type toolResp struct {
	TxID   string  `json:"tx_id"`
	Amount float64 `json:"amount"`
}

func callRefundTool(base string, params map[string]any) (*toolResp, error) {
	body, _ := json.Marshal(params)
	resp, err := http.Post(base+"/refund", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	var r toolResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

