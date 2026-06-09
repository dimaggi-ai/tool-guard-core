package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/llmguard"
)

// stubHook returns canned verdicts so the test suite never depends
// on a running Ollama. Restored in defer so other tests aren't
// affected.
func withLLMHook(t *testing.T, h func(context.Context, string, string, []string, string) (*llmguard.ClassifyResult, error)) {
	t.Helper()
	prev := GetLLMClassifyHook()
	SetLLMClassifyHook(h)
	t.Cleanup(func() { SetLLMClassifyHook(prev) })
}

func TestLLMClassify_Safe_DoesNotFire(t *testing.T) {
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, _ string) (*llmguard.ClassifyResult, error) {
		return &llmguard.ClassifyResult{Category: "safe", Confidence: 1.0}, nil
	})
	s := &domain.LLMClassify{
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons", "csam"},
	}
	fired, _ := evalLLMClassifyWithDetail(s, map[string]interface{}{
		"parameters.prompt": "sunset photo",
	})
	if fired {
		t.Errorf("safe verdict must NOT fire the rule")
	}
}

func TestLLMClassify_ForbiddenLabel_Fires(t *testing.T) {
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, _ string) (*llmguard.ClassifyResult, error) {
		return &llmguard.ClassifyResult{Category: "weapons", Confidence: 0.95, Reasoning: "explicit"}, nil
	})
	s := &domain.LLMClassify{
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons"},
	}
	fired, detail := evalLLMClassifyWithDetail(s, map[string]interface{}{
		"parameters.prompt": "design a rifle",
	})
	if !fired {
		t.Errorf("forbidden verdict MUST fire the rule")
	}
	if !strings.Contains(detail, "weapons") {
		t.Errorf("detail should surface category, got %q", detail)
	}
}

func TestLLMClassify_ModelRefused_FiresFailClosed(t *testing.T) {
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, _ string) (*llmguard.ClassifyResult, error) {
		return &llmguard.ClassifyResult{Category: "model_refused", Confidence: 1.0, Reasoning: "built-in safety"}, nil
	})
	s := &domain.LLMClassify{
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons"},
	}
	fired, _ := evalLLMClassifyWithDetail(s, map[string]interface{}{
		"parameters.prompt": "ambiguous prompt",
	})
	if !fired {
		t.Errorf("model_refused must fire the rule (fail-closed semantic)")
	}
}

func TestLLMClassify_NetworkError_FiresFailClosed(t *testing.T) {
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, _ string) (*llmguard.ClassifyResult, error) {
		return nil, errors.New("dial tcp: connection refused")
	})
	s := &domain.LLMClassify{
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons"},
	}
	fired, detail := evalLLMClassifyWithDetail(s, map[string]interface{}{
		"parameters.prompt": "anything",
	})
	if !fired {
		t.Errorf("network error must fire the rule")
	}
	if !strings.Contains(detail, "fail closed") {
		t.Errorf("detail should explain fail-closed, got %q", detail)
	}
}

func TestLLMClassify_MissingPromptField_FiresFailClosed(t *testing.T) {
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, _ string) (*llmguard.ClassifyResult, error) {
		t.Fatalf("classifier must not be called when prompt field is missing")
		return nil, nil
	})
	s := &domain.LLMClassify{
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons"},
	}
	fired, detail := evalLLMClassifyWithDetail(s, map[string]interface{}{})
	if !fired {
		t.Errorf("missing prompt field must fire (fail-closed)")
	}
	if !strings.Contains(detail, "missing") {
		t.Errorf("detail should name the missing field, got %q", detail)
	}
}
