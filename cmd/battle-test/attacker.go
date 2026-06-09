package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ollamaGenerateReq is the minimal /api/generate request shape Ollama
// accepts. Kept hand-rolled (no SDK) so this package stays dependency-free
// for the future tool-guard-core OSS extraction.
type ollamaGenerateReq struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	System  string                 `json:"system,omitempty"`
	Stream  bool                   `json:"stream"`
	Format  string                 `json:"format,omitempty"` // "json" → Ollama hard-locks output to a JSON value
	Options map[string]interface{} `json:"options,omitempty"`
}

type ollamaGenerateResp struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	EvalCount int    `json:"eval_count,omitempty"`
}

// Attacker drives one local LLM as the adversarial agent. The attacker is
// asked to emit a single JSON tool call for a given scenario; the harness
// then feeds that call into the deterministic engine to see whether the
// policy blocks it.
//
// Temperature and Seed expose the two knobs that govern reproducibility.
// A temperature of 0.0 + a fixed seed makes Ollama's outputs deterministic
// so a buyer running this harness against the same model on the same
// hardware can replay the documented block-rate table line-for-line.
// Defaults (Temperature 0.6, Seed 0 = unseeded) keep variety so the
// scenarios surface a broader set of bypass shapes; CI / regression runs
// should set both to 0 / fixed.
type Attacker struct {
	OllamaURL   string        // e.g. http://localhost:11434
	Model       string        // e.g. gemma4:e4b or qwen3:8b
	Timeout     time.Duration // per-request budget
	Temperature float64       // 0 → greedy; 0.6 → default variety
	Seed        int           // 0 → unseeded; nonzero → reproducible
	httpc       *http.Client
}

// NewAttacker prepares an attacker bound to an Ollama backend and a model.
func NewAttacker(ollamaURL, model string, timeout time.Duration) *Attacker {
	return &Attacker{
		OllamaURL:   strings.TrimRight(ollamaURL, "/"),
		Model:       model,
		Timeout:     timeout,
		Temperature: 0.6,
		Seed:        0,
		httpc:       &http.Client{Timeout: timeout + 5*time.Second},
	}
}

// AttackOutput is the tool call the attacker produced. raw is the original
// model response for the audit log; parsed is the JSON shape the harness
// uses to build the envelope.
type AttackOutput struct {
	Raw    string
	Parsed AttackToolCall
}

// AttackToolCall matches the JSON shape we ask the model to emit.
// Deliberately tiny so the model has the least chance of going off-script.
type AttackToolCall struct {
	ToolName string  `json:"tool_name"`
	Amount   float64 `json:"amount"`
	Reason   string  `json:"reason"`
}

// Attempt asks the model to bypass one scenario and returns the tool call
// it tried to make. Network and parse errors are returned so the harness
// can count them as separate outcomes (a model that fails to emit valid
// JSON is, in effect, blocked by malformedness — but we want to report
// that honestly rather than as a "policy block").
func (a *Attacker) Attempt(ctx context.Context, s Scenario) (*AttackOutput, error) {
	req := ollamaGenerateReq{
		Model:  a.Model,
		Prompt: s.UserPrompt,
		System: s.SystemPrompt,
		Stream: false,
		Format: "json", // hard-lock output to a JSON value so we can parse
		Options: map[string]interface{}{
			"temperature": a.Temperature,
			"top_p":       0.9,
			"num_predict": 200,
		},
	}
	if a.Seed != 0 {
		req.Options["seed"] = a.Seed
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.OllamaURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call ollama: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama %d: %s", resp.StatusCode, string(respBody))
	}

	var oresp ollamaGenerateResp
	if err := json.Unmarshal(respBody, &oresp); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w; body=%s", err, string(respBody))
	}

	out := &AttackOutput{Raw: oresp.Response}
	parsed, perr := extractJSONToolCall(oresp.Response)
	if perr != nil {
		// Caller will record the raw response so a human can read what the
		// model actually said; the harness treats this as "model failed to
		// produce a tool call" — distinct from "policy blocked it."
		return out, fmt.Errorf("parse model JSON: %w", perr)
	}
	out.Parsed = parsed
	return out, nil
}

// extractJSONToolCall finds the first {...} JSON object in the model's
// response and unmarshals it. Local models often wrap JSON in code fences
// or prose despite system prompts; this is tolerant of that.
func extractJSONToolCall(s string) (AttackToolCall, error) {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return AttackToolCall{}, fmt.Errorf("no JSON object in response")
	}
	raw := s[start : end+1]
	var tc AttackToolCall
	if err := json.Unmarshal([]byte(raw), &tc); err != nil {
		return AttackToolCall{}, fmt.Errorf("unmarshal %q: %w", raw, err)
	}
	if tc.ToolName == "" {
		return AttackToolCall{}, fmt.Errorf("empty tool_name")
	}
	return tc, nil
}
