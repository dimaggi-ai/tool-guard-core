package domain

import (
	"encoding/json"
	"testing"
)

func TestDeepEvalConfigUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonInput string
		wantFile  string
	}{
		{
			name:      "context_file",
			jsonInput: `{"model":"gemma4:e4b","context_file":"doc.pdf"}`,
			wantFile:  "doc.pdf",
		},
		{
			name:      "context alias",
			jsonInput: `{"model":"gemma4:e4b","context":"doc.pdf"}`,
			wantFile:  "doc.pdf",
		},
		{
			name:      "context_file takes precedence",
			jsonInput: `{"context_file":"primary.pdf","context":"backup.pdf"}`,
			wantFile:  "primary.pdf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config DeepEvalConfig
			if err := json.Unmarshal([]byte(tt.jsonInput), &config); err != nil {
				t.Fatalf("unmarshal DeepEvalConfig: %v", err)
			}
			if config.ContextFile != tt.wantFile {
				t.Fatalf("ContextFile = %q, want %q", config.ContextFile, tt.wantFile)
			}
		})
	}
}

func TestPolicyUnmarshalJSONPreservesDeepEvaluationCompatibility(t *testing.T) {
	input := `{
		"policy_id":"test-policy",
		"deep_evaluation":{"model":"gemma4:e4b","context":"clinical-guidance"}
	}`

	var policy Policy
	if err := json.Unmarshal([]byte(input), &policy); err != nil {
		t.Fatalf("unmarshal Policy: %v", err)
	}
	if policy.DeepEvaluation == nil {
		t.Fatal("DeepEvaluation is nil")
	}
	if policy.DeepEvaluation.ContextFile != "clinical-guidance" {
		t.Fatalf("ContextFile = %q, want clinical-guidance", policy.DeepEvaluation.ContextFile)
	}
}
