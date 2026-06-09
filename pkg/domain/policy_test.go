package domain

import (
	"encoding/json"
	"testing"
)

func TestDeepEvalConfig_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonInput string
		wantFile  string
	}{
		{
			name:      "supports context_file",
			jsonInput: `{"model":"gemma4:e4b","context_file":"doc.pdf"}`,
			wantFile:  "doc.pdf",
		},
		{
			name:      "supports context alias from YAML mapping",
			jsonInput: `{"model":"gemma4:e4b","context":"doc.pdf"}`,
			wantFile:  "doc.pdf",
		},
		{
			name:      "prefers context_file if both present",
			jsonInput: `{"model":"gemma4:e4b","context_file":"primary.pdf","context":"backup.pdf"}`,
			wantFile:  "primary.pdf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config DeepEvalConfig
			if err := json.Unmarshal([]byte(tt.jsonInput), &config); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if config.ContextFile != tt.wantFile {
				t.Errorf("got ContextFile = %q, want %q", config.ContextFile, tt.wantFile)
			}
		})
	}
}

func TestPolicy_UnmarshalJSON_NestedDeepEvaluation(t *testing.T) {
	jsonInput := `{
		"policy_id": "test-policy",
		"name": "Test Policy",
		"deep_evaluation": {
			"model": "gemma4:e4b",
			"context": "nested-context.pdf"
		}
	}`

	var p Policy
	if err := json.Unmarshal([]byte(jsonInput), &p); err != nil {
		t.Fatalf("failed to unmarshal policy: %v", err)
	}

	if p.DeepEvaluation == nil {
		t.Fatal("expected DeepEvaluation to be non-nil")
	}

	if p.DeepEvaluation.ContextFile != "nested-context.pdf" {
		t.Errorf("got nested ContextFile = %q, want %q", p.DeepEvaluation.ContextFile, "nested-context.pdf")
	}
}
