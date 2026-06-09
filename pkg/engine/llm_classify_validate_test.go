package engine

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestValidatePolicy_LLMClassify_LabelSanitization covers the
// validation gaps the trinity review surfaced: the validator must
// refuse to load a policy whose Forbidden list contains "safe", any
// reserved special label, duplicates, comma/quote/newline characters,
// whitespace-only entries, an oversize list, or a bad OllamaURL.
func TestValidatePolicy_LLMClassify_LabelSanitization(t *testing.T) {
	mkpolicy := func(lc domain.LLMClassify) *domain.Policy {
		return &domain.Policy{
			PolicyID: "test",
			Rules: []domain.Rule{{
				RuleID:     "r",
				Conditions: domain.Condition{LLMClassify: &lc},
				Effect:     domain.EffectDeny,
			}},
		}
	}
	cases := []struct {
		name string
		lc   domain.LLMClassify
		want string
	}{
		{
			name: "safe label rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "safe"}},
			want: "silently never fire",
		},
		{
			name: "model_refused label rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"model_refused"}},
			want: "reserved",
		},
		{
			name: "whitespace-only label rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"   "}},
			want: "whitespace-only",
		},
		{
			name: "comma label rejected (closed-set injection)",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "x, safe"}},
			want: "disallowed character",
		},
		{
			name: "newline label rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "x\nsafe"}},
			want: "disallowed character",
		},
		{
			name: "quote label rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"x\""}},
			want: "disallowed character",
		},
		{
			name: "duplicate labels rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "weapons"}},
			want: "duplicate",
		},
		{
			name: "case-fold duplicate rejected",
			lc:   domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "Weapons"}},
			want: "duplicate",
		},
		{
			name: "bad ollama URL scheme rejected",
			lc: domain.LLMClassify{
				PromptField: "parameters.prompt",
				Forbidden:   []string{"weapons"},
				OllamaURL:   "ftp://x/",
			},
			want: "scheme",
		},
		{
			name: "negative timeout rejected",
			lc: domain.LLMClassify{
				PromptField:    "parameters.prompt",
				Forbidden:      []string{"weapons"},
				TimeoutSeconds: -1,
			},
			want: "timeout_seconds",
		},
		{
			name: "huge timeout rejected",
			lc: domain.LLMClassify{
				PromptField:    "parameters.prompt",
				Forbidden:      []string{"weapons"},
				TimeoutSeconds: 999,
			},
			want: "timeout_seconds",
		},
	}
	for _, tc := range cases {
		err := ValidatePolicy(mkpolicy(tc.lc))
		if err == nil {
			t.Errorf("%s: expected validation error, got nil", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q should mention %q", tc.name, err.Error(), tc.want)
		}
	}

	// Sanity: a valid LLMClassify still loads.
	ok := domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: []string{"weapons", "csam"}}
	if err := ValidatePolicy(mkpolicy(ok)); err != nil {
		t.Errorf("clean policy should validate, got %v", err)
	}
}

// TestValidatePolicy_LLMClassify_ForbiddenListSize caps the list at
// 64 to bound the system-prompt size.
func TestValidatePolicy_LLMClassify_ForbiddenListSize(t *testing.T) {
	huge := make([]string, 65)
	for i := range huge {
		huge[i] = "cat_" + string(rune('a'+(i%26))) + "_" + string(rune('a'+(i/26)))
	}
	lc := domain.LLMClassify{PromptField: "parameters.prompt", Forbidden: huge}
	err := ValidatePolicy(&domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{{
			RuleID:     "r",
			Conditions: domain.Condition{LLMClassify: &lc},
			Effect:     domain.EffectDeny,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "≤64") {
		t.Errorf("expected ≤64-label cap error, got %v", err)
	}
}
