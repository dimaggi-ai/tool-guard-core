// mcp-server is a minimal MCP-style stdio server that gates every
// tool call through Tool Guard before invoking the upstream tool.
//
// It implements just enough of the Model Context Protocol over JSON-RPC
// 2.0 stdio framing to demonstrate the integration pattern:
//   - initialize
//   - tools/list
//   - tools/call  (each call goes through tg-proxy /evaluate first)
//
// The server exposes two example tools:
//   - issue_refund (parameters: amount, reason)
//   - export_customer_data (parameters: row_count, fields,
//     customer_id_count, legal_hold_ticket,
//     customer_status)
//
// Both are MOCKED — they don't actually issue refunds or export rows.
// The point is that any MCP client (Claude Desktop, Continue.dev, the
// MCP-rs reference client, etc.) can connect over stdio, list the two
// tools, and watch Tool Guard deny over-cap refunds or unflagged
// PII exports.
//
// Run with a Tool Guard proxy already up:
//
//	./bin/tg-proxy -policy-dir ./policies -audit-log /tmp/mcp.jsonl &
//	go run ./examples/mcp-server -tg-proxy http://127.0.0.1:9090
//
// The server reads JSON-RPC requests from stdin and writes responses
// to stdout. An MCP client speaks stdio.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	tgProxy := flag.String("tg-proxy", "http://127.0.0.1:9090", "Tool Guard proxy base URL")
	agentID := flag.String("agent-id", "mcp-bridge", "agent_id sent to tg-proxy")
	orgID := flag.String("org-id", "demo", "org_id sent to tg-proxy")
	framing := flag.String("framing", "auto", "stdio message framing: auto | length-prefixed | line-delimited")
	flag.Parse()

	// The MCP stdio transport spec
	// (https://modelcontextprotocol.io/specification/server/transports/stdio)
	// uses newline-delimited JSON-RPC messages — one JSON object per
	// line, no embedded newlines. That is what `line-delimited` does
	// here, and it is the correct mode for any spec-conforming MCP
	// client (Claude Desktop, Continue.dev, MCP-rs).
	//
	// We ALSO support `length-prefixed`: LSP-style `Content-Length: N`
	// headers followed by exactly N bytes. This is the framing the
	// Language Server Protocol uses and some MCP-client adapters
	// (especially proxies bridging MCP and LSP, or non-conforming
	// implementations) expect. It is NOT required by the MCP spec.
	//
	// auto: peek the first byte; '{' → line-delimited, 'C' (start of
	// `Content-Length:`) → length-prefixed.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("mcp-server starting; tg-proxy=%s framing=%s", *tgProxy, *framing)

	srv := &server{
		tgProxy: *tgProxy,
		agentID: *agentID,
		orgID:   *orgID,
		http:    &http.Client{Timeout: 10 * time.Second},
	}

	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	if *framing == "auto" {
		first, err := reader.Peek(1)
		if err != nil {
			return
		}
		if first[0] == 'C' {
			*framing = "length-prefixed"
		} else {
			*framing = "line-delimited"
		}
	}
	log.Printf("mcp-server using framing=%s", *framing)

	for {
		var raw []byte
		var err error
		if *framing == "length-prefixed" {
			raw, err = readLengthPrefixed(reader)
		} else {
			raw, err = readLineDelimited(reader)
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("stdin: %v", err)
			return
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		srv.framing = *framing
		var req jsonRPCRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			srv.writeError(nil, -32700, "parse error: "+err.Error())
			continue
		}
		srv.handle(&req)
	}
}

// readLineDelimited reads one newline-terminated JSON message.
func readLineDelimited(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// readLengthPrefixed reads LSP-style framed JSON.
// Headers:
//
//	Content-Length: 1234\r\n
//	Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n   (optional)
//	\r\n
//	<exactly 1234 bytes of JSON>
func readLengthPrefixed(r *bufio.Reader) ([]byte, error) {
	contentLen := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			n, perr := strconv.Atoi(strings.TrimSpace(line[len("Content-Length:"):]))
			if perr != nil {
				return nil, fmt.Errorf("bad Content-Length: %v", perr)
			}
			contentLen = n
		}
	}
	if contentLen < 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}
	if contentLen > 1<<22 {
		return nil, fmt.Errorf("content-length %d exceeds 4 MiB cap", contentLen)
	}
	buf := make([]byte, contentLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type server struct {
	tgProxy string
	agentID string
	orgID   string
	framing string // "length-prefixed" or "line-delimited"
	http    *http.Client
}

func (s *server) handle(req *jsonRPCRequest) {
	// JSON-RPC 2.0 notifications have no `id` field — the server
	// MUST NOT respond. MCP `notifications/initialized`, `notifications/cancelled`,
	// and `notifications/progress` arrive here and silently no-op.
	if len(req.ID) == 0 {
		log.Printf("notification: %s", req.Method)
		return
	}
	switch req.Method {
	case "initialize":
		s.write(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "tool-guard-mcp-bridge",
				"version": "0.1.0",
			},
		})
	case "tools/list":
		s.write(req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "issue_refund",
					"description": "Issue a customer refund. GATED BY TOOL GUARD — over-cap requests will be denied.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"amount": map[string]any{"type": "number"},
							"reason": map[string]any{"type": "string"},
						},
						"required": []string{"amount", "reason"},
					},
				},
				{
					"name":        "export_customer_data",
					"description": "Export customer records. GATED BY TOOL GUARD — over-cap / PII without legal-hold / erased-customer requests will be denied.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"row_count":         map[string]any{"type": "number"},
							"customer_id_count": map[string]any{"type": "number"},
							"fields":            map[string]any{"type": "string"},
							"legal_hold_ticket": map[string]any{"type": "string"},
							"customer_status":   map[string]any{"type": "string"},
						},
					},
				},
			},
		})
	case "tools/call":
		s.handleToolCall(req)
	default:
		s.writeError(req.ID, -32601, "method not found: "+req.Method)
	}
}

func (s *server) handleToolCall(req *jsonRPCRequest) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.writeError(req.ID, -32602, "invalid params: "+err.Error())
		return
	}

	// Map the MCP tool name to a Tool Guard tool_group. In production
	// this mapping is part of the operator's deployment config; here
	// we inline it for clarity.
	toolGroup := map[string]string{
		"issue_refund":         "monetary_outflow",
		"export_customer_data": "data_export",
	}[p.Name]

	envelope := map[string]any{
		"envelope_id": fmt.Sprintf("mcp-%d", time.Now().UnixNano()),
		"agent_id":    s.agentID,
		"session_id":  "mcp-stdio",
		"org_id":      s.orgID,
		"tool_name":   p.Name,
		"tool_group":  toolGroup,
		"parameters":  json.RawMessage(p.Arguments),
	}
	body, _ := json.Marshal(envelope)
	resp, err := s.http.Post(s.tgProxy+"/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		s.toolCallResult(req.ID, "tool guard unreachable: "+err.Error(), true)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var evalResult struct {
		Decision       string `json:"decision"`
		ActionTaken    string `json:"action_taken"`
		DecisionReason string `json:"decision_reason"`
	}
	if err := json.Unmarshal(respBody, &evalResult); err != nil {
		s.toolCallResult(req.ID, "tool guard returned invalid JSON: "+err.Error(), true)
		return
	}

	log.Printf("tool=%s decision=%s reason=%q", p.Name, evalResult.Decision, evalResult.DecisionReason)

	switch evalResult.Decision {
	case "allowed":
		// Fake the tool execution. In a real deployment this would
		// call the actual upstream tool (Stripe, the customer DB,
		// etc.).
		s.toolCallResult(req.ID, fmt.Sprintf("[STUB] %s executed successfully", p.Name), false)
	case "denied":
		s.toolCallResult(req.ID, "DENIED BY POLICY: "+evalResult.DecisionReason, true)
	case "escalated":
		s.toolCallResult(req.ID, "ESCALATED FOR HUMAN APPROVAL: "+evalResult.DecisionReason, true)
	case "flagged":
		s.toolCallResult(req.ID, fmt.Sprintf("[STUB] %s executed (flagged for review): %s", p.Name, evalResult.DecisionReason), false)
	default:
		s.toolCallResult(req.ID, "unknown decision: "+evalResult.Decision, true)
	}
}

// toolCallResult writes an MCP tools/call response. MCP's content
// model has typed parts; we use a single text block which is
// supported by every MCP client.
func (s *server) toolCallResult(id json.RawMessage, text string, isError bool) {
	s.write(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"isError": isError,
	})
}

func (s *server) write(id json.RawMessage, result any) {
	if id == nil {
		// notifications get no response
		return
	}
	s.emit(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *server) writeError(id json.RawMessage, code int, message string) {
	s.emit(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	})
}

// emit serialises one JSON-RPC response to stdout using the negotiated
// stdio framing. Line-delimited (one JSON object per newline) is the
// MCP stdio transport spec mode used by conforming clients; the
// length-prefixed Content-Length form is the LSP-compatibility mode
// only — see the framing note at the top of this file.
func (s *server) emit(resp jsonRPCResponse) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		log.Printf("emit: %v", err)
		return
	}
	body := bytes.TrimRight(buf.Bytes(), "\n")
	if s.framing == "length-prefixed" {
		fmt.Fprintf(os.Stdout, "Content-Length: %d\r\n\r\n", len(body))
		_, _ = os.Stdout.Write(body)
	} else {
		_, _ = os.Stdout.Write(body)
		_, _ = os.Stdout.Write([]byte{'\n'})
	}
}
