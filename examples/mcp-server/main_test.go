package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleToolCallUsesAppliedAction(t *testing.T) {
	tests := []struct {
		name      string
		decision  string
		action    string
		wantError bool
		wantText  string
	}{
		{
			name:      "shadow deny proceeds",
			decision:  "denied",
			action:    "allowed_shadow",
			wantError: false,
			wantText:  "executed successfully",
		},
		{
			name:      "flag proceeds",
			decision:  "flagged",
			action:    "flagged",
			wantError: false,
			wantText:  "flagged for review",
		},
		{
			name:      "deny blocks",
			decision:  "denied",
			action:    "denied",
			wantError: true,
			wantText:  "DENIED BY POLICY",
		},
		{
			name:      "unknown fails closed",
			decision:  "allowed",
			action:    "future_action",
			wantError: true,
			wantText:  "unknown action_taken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/evaluate" {
					t.Fatalf("path = %q, want /evaluate", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"decision":        tt.decision,
					"action_taken":    tt.action,
					"decision_reason": "test reason",
				})
			}))
			defer proxy.Close()

			params, err := json.Marshal(map[string]any{
				"name":      "issue_refund",
				"arguments": map[string]any{"amount": 750, "reason": "test"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			s := &server{
				tgProxy: proxy.URL,
				agentID: "test-agent",
				orgID:   "test-org",
				framing: "line-delimited",
				http:    proxy.Client(),
				out:     &out,
			}
			s.handleToolCall(&jsonRPCRequest{
				JSONRPC: "2.0",
				ID:      json.RawMessage("1"),
				Method:  "tools/call",
				Params:  params,
			})

			var got struct {
				Result struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
					IsError bool `json:"isError"`
				} `json:"result"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &got); err != nil {
				t.Fatalf("decode MCP response: %v; body=%s", err, out.String())
			}
			if got.Result.IsError != tt.wantError {
				t.Errorf("isError = %v, want %v; body=%s", got.Result.IsError, tt.wantError, out.String())
			}
			if len(got.Result.Content) != 1 || !strings.Contains(got.Result.Content[0].Text, tt.wantText) {
				t.Errorf("content = %#v, want text containing %q", got.Result.Content, tt.wantText)
			}
		})
	}
}
