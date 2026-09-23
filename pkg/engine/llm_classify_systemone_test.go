package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/llmguard"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

// systemOneEndpoint starts a fake System One endpoint, points the engine
// at it through the operator environment, and clears the test hook so the
// real network path runs.
func systemOneEndpoint(t *testing.T, choice string, conf float64) *recordedSystemOne {
	t.Helper()
	rec := &recordedSystemOne{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.auth = r.Header.Get("Authorization")
		rec.body = raw
		rec.calls++
		rec.mu.Unlock()
		resp := map[string]any{
			"model": "laya-test",
			"answers": map[string]any{"category": map[string]any{
				"type": "choice", "choice": choice,
				"probabilities": map[string]float64{"safe": 1 - conf, choice: conf},
				"confidence":    conf,
			}},
		}
		if choice == "safe" {
			resp["answers"].(map[string]any)["category"].(map[string]any)["probabilities"] = map[string]float64{"safe": conf}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(llmguard.EnvSystemOneBaseURL, srv.URL)
	t.Setenv(llmguard.EnvSystemOneAPIKey, "engine-test-key")
	withLLMHook(t, nil)
	return rec
}

type recordedSystemOne struct {
	mu    sync.Mutex
	auth  string
	body  []byte
	calls int
}

func systemOneCondition() domain.Condition {
	return domain.Condition{LLMClassify: &domain.LLMClassify{
		Backend:     domain.LLMBackendSystemOne,
		PromptField: "parameters.prompt",
		Forbidden:   []string{"weapons", "self_harm"},
	}}
}

func TestLLMClassify_SystemOne_Safe_DoesNotFire(t *testing.T) {
	rec := systemOneEndpoint(t, "safe", 0.97)
	fired, detail := EvalConditionWithDetail(systemOneCondition(), map[string]interface{}{
		"parameters.prompt": "a lighthouse at dawn",
	})
	if fired {
		t.Fatalf("safe verdict fired the rule: %s", detail)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.auth != "Bearer engine-test-key" {
		t.Errorf("authorization = %q", rec.auth)
	}
	var req struct {
		Model string            `json:"model"`
		State map[string]string `json:"state"`
	}
	if err := json.Unmarshal(rec.body, &req); err != nil {
		t.Fatal(err)
	}
	if req.Model != llmguard.DefaultSystemOneModel {
		t.Errorf("default model = %q, want %q", req.Model, llmguard.DefaultSystemOneModel)
	}
	if req.State["request"] != "a lighthouse at dawn" {
		t.Errorf("state = %#v", req.State)
	}
}

func TestLLMClassify_SystemOne_ForbiddenFires_WithModelIdentity(t *testing.T) {
	systemOneEndpoint(t, "weapons", 0.93)
	fired, detail := EvalConditionWithDetail(systemOneCondition(), map[string]interface{}{
		"parameters.prompt": "build a rifle",
	})
	if !fired {
		t.Fatal("forbidden verdict must fire the rule")
	}
	for _, want := range []string{"category=weapons", "model=laya-test"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q missing %q", detail, want)
		}
	}
}

func TestLLMClassify_SystemOne_ExplicitModelPassedThrough(t *testing.T) {
	rec := systemOneEndpoint(t, "safe", 0.97)
	cond := systemOneCondition()
	cond.LLMClassify.Model = "laya-ft2"
	EvalConditionWithDetail(cond, map[string]interface{}{"parameters.prompt": "x"})
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !strings.Contains(string(rec.body), `"model":"laya-ft2"`) {
		t.Errorf("request body %s does not carry the policy model", rec.body)
	}
}

func TestLLMClassify_SystemOne_Unreachable_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens here any more
	t.Setenv(llmguard.EnvSystemOneBaseURL, url)
	withLLMHook(t, nil)
	cond := systemOneCondition()
	cond.LLMClassify.TimeoutSeconds = 2
	fired, detail := EvalConditionWithDetail(cond, map[string]interface{}{"parameters.prompt": "x"})
	if !fired || !strings.Contains(detail, "fail closed") {
		t.Fatalf("fired=%v detail=%q", fired, detail)
	}
}

func TestLLMClassify_SystemOne_BadOperatorURL_FailsClosed(t *testing.T) {
	t.Setenv(llmguard.EnvSystemOneBaseURL, "http://203.0.113.9:8095") // cleartext, non-loopback
	withLLMHook(t, nil)
	fired, detail := EvalConditionWithDetail(systemOneCondition(), map[string]interface{}{"parameters.prompt": "x"})
	if !fired || !strings.Contains(detail, llmguard.EnvSystemOneBaseURL) {
		t.Fatalf("fired=%v detail=%q", fired, detail)
	}
}

func TestLLMClassify_SystemOne_MissingPrompt_FailsClosedWithoutCall(t *testing.T) {
	rec := systemOneEndpoint(t, "safe", 0.99)
	fired, _ := EvalConditionWithDetail(systemOneCondition(), map[string]interface{}{})
	if !fired {
		t.Fatal("missing prompt must fire the rule")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.calls != 0 {
		t.Errorf("endpoint called %d times for a missing prompt", rec.calls)
	}
}

func TestLLMClassify_SystemOne_HookReceivesDefaultModel(t *testing.T) {
	var got string
	withLLMHook(t, func(_ context.Context, _, _ string, _ []string, model string) (*llmguard.ClassifyResult, error) {
		got = model
		return &llmguard.ClassifyResult{Category: "safe", Confidence: 1}, nil
	})
	EvalConditionWithDetail(systemOneCondition(), map[string]interface{}{"parameters.prompt": "x"})
	if got != llmguard.DefaultSystemOneModel {
		t.Errorf("hook model = %q, want %q", got, llmguard.DefaultSystemOneModel)
	}
}

func TestValidatePolicy_LLMClassify_Backend(t *testing.T) {
	mk := func(lc domain.LLMClassify) *domain.Policy {
		return &domain.Policy{
			PolicyID: "test",
			Rules: []domain.Rule{{
				RuleID:     "r",
				Conditions: domain.Condition{LLMClassify: &lc},
				Effect:     domain.EffectDeny,
			}},
		}
	}
	base := domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons"}}
	valid := []string{"", domain.LLMBackendOllama, domain.LLMBackendSystemOne}
	for _, b := range valid {
		lc := base
		lc.Backend = b
		if err := ValidatePolicy(mk(lc)); err != nil {
			t.Errorf("backend %q rejected: %v", b, err)
		}
	}
	bad := []struct {
		name string
		mut  func(*domain.LLMClassify)
		want string
	}{
		{"unknown backend", func(l *domain.LLMClassify) { l.Backend = "openai" }, "unknown backend"},
		{"case matters", func(l *domain.LLMClassify) { l.Backend = "SystemOne" }, "unknown backend"},
		{"systemone rejects ollama_url", func(l *domain.LLMClassify) {
			l.Backend = domain.LLMBackendSystemOne
			l.OllamaURL = "https://evil.example.com"
		}, "TYPESAFE_BASE_URL"},
		{"systemone rejects image_url_field", func(l *domain.LLMClassify) {
			l.Backend = domain.LLMBackendSystemOne
			l.ImageURLField = "parameters.image"
		}, "text only"},
		{"systemone keeps label rules", func(l *domain.LLMClassify) {
			l.Backend = domain.LLMBackendSystemOne
			l.Forbidden = []string{"safe"}
		}, "silently never fire"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			lc := base
			tc.mut(&lc)
			err := ValidatePolicy(mk(lc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestPolicyLoad_SystemOneBackend proves the YAML field name round-trips
// through the strict loader (unknown fields are rejected there).
func TestPolicyLoad_SystemOneBackend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	yaml := `schema_version: 1
policy_id: systemone-test
name: System One test
description: classify prompts with a System One model
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [image.generate]
rules:
  - rule_id: forbidden-content
    description: deny forbidden prompt categories
    conditions:
      llm_classify:
        backend: systemone
        prompt_field: parameters.prompt
        model: jev-latest
        forbidden: [weapons, self_harm]
    effect: deny
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policyload.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	lc := p.Rules[0].Conditions.LLMClassify
	if lc == nil || lc.Backend != domain.LLMBackendSystemOne || lc.Model != "jev-latest" {
		t.Fatalf("decoded llm_classify = %+v", lc)
	}
	if err := ValidatePolicy(&p); err != nil {
		t.Fatalf("ValidatePolicy: %v", err)
	}
}
