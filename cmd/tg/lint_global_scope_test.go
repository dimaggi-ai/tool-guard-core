package main

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// scope.intentionally_global suppresses policy-scope-leak: a declared floor
// is a design, not a leak.
func TestLint_IntentionallyGlobalSuppressesScopeLeak(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{IntentionallyGlobal: true},
	}
	for _, f := range lintPolicy(p) {
		if f.Rule == "policy-scope-leak" {
			t.Errorf("policy-scope-leak must be suppressed when intentionally_global is declared; got: %q", f.Message)
		}
	}
}

// An undeclared empty scope still warns — the suppression must be explicit.
func TestLint_UndeclaredEmptyScopeStillWarns(t *testing.T) {
	p := domain.Policy{}
	found := false
	for _, f := range lintPolicy(p) {
		if f.Rule == "policy-scope-leak" {
			found = true
		}
	}
	if !found {
		t.Error("empty scope without intentionally_global must still produce policy-scope-leak")
	}
}

// Declaring global intent while ALSO setting tool selectors is a
// contradiction — the selectors gate matching, so the policy is not global.
func TestLint_GlobalScopeContradiction(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			IntentionallyGlobal: true,
			ToolNames:           []string{"bash"},
		},
	}
	found := false
	for _, f := range lintPolicy(p) {
		if f.Rule == "global-scope-contradiction" {
			found = true
		}
	}
	if !found {
		t.Error("intentionally_global + tool selectors must produce global-scope-contradiction")
	}
}
