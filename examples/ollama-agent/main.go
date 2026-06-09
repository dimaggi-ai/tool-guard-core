// ollama-agent is the real-LLM end-to-end demo for Tool Guard Core.
//
// It opens a conversation with a local Ollama model (gemma4:e4b by
// default), gives the model exactly one tool (issue_refund), sends a
// user message that needs that tool, then runs a tool-use loop. Every
// time the model wants to call the tool the agent:
//
//   1. forwards the tool call to tg-proxy /evaluate
//   2. on allowed → calls the real refund-tool, returns success to the model
//   3. on denied / escalated → returns the policy's suggested response
//      to the model as a tool error so the model can adapt
//
// The transcript prints live to stdout so an operator watching the
// terminal sees the actual conversation: model reasoning, blocked
// attempt, model adapting, smaller attempt allowed, final response.
//
// Why JSON-mode instead of Ollama's native tool-calling? Ollama's
// `tools` parameter support varies per model template. Asking the
// model to emit a strict JSON {action, tool, arguments | content}
// object via `format: "json"` works reliably with gemma4:e4b and any
// other Ollama model — and demonstrates exactly the same flow.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// systemPrompt tells the model the rules of the conversation. It is
// kept intentionally direct because local models drift off-script when
// the prompt rambles. The decision schema is deliberately closed-set so
// `format: json` can't return something we can't parse.
const systemPrompt = `You are a customer-support assistant for an online store.

You have exactly ONE tool you can call:

  issue_refund(amount: number USD, customer_id: string, reason: string)

Every reply you give MUST be a single JSON object. Two shapes are allowed.

To use the tool:
  {"action": "call_tool", "tool": "issue_refund", "arguments": {"amount": <number>, "customer_id": "<string>", "reason": "<string>"}}

To finish the conversation with a message for the user:
  {"action": "respond", "content": "<your message>"}

Rules:
- Output ONLY the JSON object. No prose. No markdown. No code fences.
- If a tool call is blocked, the next system message will tell you why.
  React: pick a smaller amount, change the approach, or finalize with
  a "respond" explaining the limitation to the user.
- Never call the tool with the same arguments twice.
- After you have either successfully refunded the customer OR explained
  why you cannot, emit a "respond" and stop.`

// modelTurn is the JSON object we ask the model to emit on every turn.
type modelTurn struct {
	Action    string         `json:"action"`              // "call_tool" | "respond"
	Tool      string         `json:"tool,omitempty"`      // only when action=call_tool
	Arguments map[string]any `json:"arguments,omitempty"` // only when action=call_tool
	Content   string         `json:"content,omitempty"`   // only when action=respond
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatReq struct {
	Model    string         `json:"model"`
	Messages []message      `json:"messages"`
	Format   string         `json:"format,omitempty"`
	Stream   bool           `json:"stream"`
	Options  map[string]any `json:"options,omitempty"`
}

type ollamaChatResp struct {
	Message message `json:"message"`
	Done    bool    `json:"done"`
}

type envelope struct {
	AgentID    string         `json:"agent_id"`
	SessionID  string         `json:"session_id"`
	OrgID      string         `json:"org_id"`
	ToolName   string         `json:"tool_name"`
	ToolGroup  string         `json:"tool_group"`
	Parameters map[string]any `json:"parameters"`
}

type proxyDecision struct {
	Decision          string `json:"decision"`
	ActionTaken       string `json:"action_taken"`
	DecisionReason    string `json:"decision_reason"`
	SuggestedResponse string `json:"suggested_response"`
}

type toolResp struct {
	OK     bool    `json:"ok"`
	TxID   string  `json:"tx_id"`
	Amount float64 `json:"amount"`
}

func main() {
	ollamaURL := flag.String("ollama", "http://localhost:11434", "Ollama base URL")
	modelName := flag.String("model", "gemma4:e4b", "Ollama model tag")
	proxyURL := flag.String("proxy", "http://localhost:19090", "tg-proxy base URL")
	toolURL := flag.String("tool", "http://localhost:18080", "refund-tool base URL")
	userMsg := flag.String("user", "I had a damaged item from order ORD-9912 (customer CUST-001). I'd like a full refund of $1000 please.", "User message that kicks off the conversation")
	maxTurns := flag.Int("max-turns", 8, "Maximum conversation turns before giving up")
	flag.Parse()

	sessionID := fmt.Sprintf("sess-%d", time.Now().Unix())

	messages := []message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: *userMsg},
	}

	hr()
	fmt.Printf("model:    %s\n", *modelName)
	fmt.Printf("policy:   tg-proxy at %s\n", *proxyURL)
	fmt.Printf("tool:     refund-tool at %s\n", *toolURL)
	fmt.Printf("session:  %s\n\n", sessionID)
	fmt.Printf("[user]    %s\n", *userMsg)

	const maxHiccups = 5 // empty / malformed model replies in a row before we give up

	hiccups := 0
	for turn := 1; turn <= *maxTurns; turn++ {
		hr()
		fmt.Printf("--- turn %d ---\n", turn)

		// 1. Ask the model what to do next.
		t0 := time.Now()
		resp, err := chat(*ollamaURL, *modelName, messages)
		if err != nil {
			log.Fatalf("ollama: %v", err)
		}
		raw := strings.TrimSpace(resp.Message.Content)
		elapsed := time.Since(t0)

		// Empty response — small local models sometimes give up under
		// format:json + format=json. Don't count it as a real turn;
		// retry up to maxHiccups times before bailing.
		if raw == "" {
			hiccups++
			fmt.Printf("[hiccup]  (%dms) model returned empty content (%d/%d)\n", elapsed.Milliseconds(), hiccups, maxHiccups)
			if hiccups >= maxHiccups {
				log.Fatalf("model returned %d empty responses in a row; aborting", maxHiccups)
			}
			turn-- // don't bill this against the turn budget
			continue
		}
		hiccups = 0
		fmt.Printf("[model]   (%dms) %s\n", elapsed.Milliseconds(), oneLine(raw))

		// Append the assistant turn to the conversation history so the
		// model sees what it said.
		messages = append(messages, message{Role: "assistant", Content: raw})

		// 2. Parse the model's JSON. If it goes off-script, tell it so
		//    and let it self-correct on the next turn.
		var dec modelTurn
		if err := json.Unmarshal([]byte(raw), &dec); err != nil {
			fmt.Printf("[error]   model output not parseable as JSON; asking it to retry\n")
			messages = append(messages, message{Role: "user", Content: "Your previous reply was not valid JSON. Reply with one of the two allowed JSON shapes only."})
			continue
		}

		switch dec.Action {
		case "respond":
			hr()
			fmt.Printf("[final]   %s\n", dec.Content)
			hr()
			return

		case "call_tool":
			if dec.Tool != "issue_refund" {
				fmt.Printf("[error]   model tried unknown tool %q; rejecting\n", dec.Tool)
				messages = append(messages, message{Role: "user", Content: fmt.Sprintf("Tool %q does not exist. Only issue_refund is available.", dec.Tool)})
				continue
			}
			// 3. Forward to tg-proxy for the policy decision.
			env := envelope{
				AgentID:    "ollama-demo-agent",
				SessionID:  sessionID,
				OrgID:      "demo-org",
				ToolName:   dec.Tool,
				ToolGroup:  "monetary_outflow",
				Parameters: dec.Arguments,
			}
			pd, err := evaluate(*proxyURL, env)
			if err != nil {
				log.Fatalf("tg-proxy: %v", err)
			}
			fmt.Printf("[proxy]   %s — %s\n", pd.Decision, oneLine(pd.DecisionReason))

			switch pd.ActionTaken {
			case "allowed", "allowed_shadow":
				// 4a. Allowed → actually call the tool, return the
				//     real result to the model.
				out, err := callTool(*toolURL, dec.Arguments)
				if err != nil {
					log.Fatalf("refund-tool: %v", err)
				}
				fmt.Printf("[tool]    refunded $%.2f, tx=%s\n", out.Amount, out.TxID)
				messages = append(messages, message{
					Role:    "user",
					Content: fmt.Sprintf("[tool-result] success: refund processed. tx_id=%s amount=$%.2f. Confirm to the user and stop.", out.TxID, out.Amount),
				})
			case "denied", "escalated":
				// 4b. Blocked → tell the model what happened. The
				//     suggested_response is the policy author's
				//     recommended phrasing back to the user. The
				//     guidance below is deliberately heavy-handed
				//     because small local models (gemma4:e4b) need
				//     explicit shape reminders to stay on-script
				//     across multi-turn JSON conversations.
				note := pd.SuggestedResponse
				if note == "" {
					note = pd.DecisionReason
				}
				messages = append(messages, message{
					Role: "user",
					Content: fmt.Sprintf(
						"[tool-result] BLOCKED by policy. Decision: %s. Policy note: %s\n\n"+
							"You MUST reply with EXACTLY ONE JSON object — no prose, no empty content.\n"+
							"Pick ONE:\n"+
							"  (A) try again with smaller arguments (amount strictly below $500):\n"+
							"      {\"action\":\"call_tool\",\"tool\":\"issue_refund\",\"arguments\":{\"amount\":<N>,\"customer_id\":\"...\",\"reason\":\"...\"}}\n"+
							"  (B) stop and tell the user:\n"+
							"      {\"action\":\"respond\",\"content\":\"...\"}",
						pd.ActionTaken, note,
					),
				})
			default:
				log.Fatalf("unexpected proxy action_taken=%q", pd.ActionTaken)
			}

		default:
			fmt.Printf("[error]   unknown action %q\n", dec.Action)
			messages = append(messages, message{Role: "user", Content: `Use one of the two JSON shapes: {"action":"call_tool",...} or {"action":"respond","content":"..."}.`})
		}
	}

	hr()
	fmt.Printf("[done]    hit max-turns=%d without final respond — try raising -max-turns\n", *maxTurns)
}

// ── helpers ────────────────────────────────────────────────────────────────

func chat(base, model string, messages []message) (*ollamaChatResp, error) {
	req := ollamaChatReq{
		Model:    model,
		Messages: messages,
		Format:   "json",
		Stream:   false,
		Options: map[string]any{
			// Modest temperature: low enough to keep the JSON shape,
			// high enough that retries explore new replies instead of
			// repeating the same empty response.
			"temperature": 0.5,
			"top_p":       0.9,
			"num_predict": 256,
		},
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(base+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama %d: %s", resp.StatusCode, string(b))
	}
	var out ollamaChatResp
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func evaluate(base string, env envelope) (*proxyDecision, error) {
	body, _ := json.Marshal(env)
	resp, err := http.Post(base+"/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tg-proxy %d: %s", resp.StatusCode, string(b))
	}
	var d proxyDecision
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func callTool(base string, args map[string]any) (*toolResp, error) {
	body, _ := json.Marshal(args)
	resp, err := http.Post(base+"/refund", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refund-tool %d: %s", resp.StatusCode, string(b))
	}
	var r toolResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func hr() {
	fmt.Fprintln(os.Stdout, strings.Repeat("─", 72))
}

// oneLine collapses a multi-line string into a single line for terminal
// readability. The full transcript still lives in the conversation
// history; this is only for the live print.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}
