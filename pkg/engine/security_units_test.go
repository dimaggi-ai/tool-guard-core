package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/llmguard"
)

// TestValidateOllamaURL covers the SSRF-relevant URL allowlist used when
// a policy supplies a custom ollama_url. Anything that isn't a clean
// http/https URL without userinfo must be rejected at load time.
func TestValidateOllamaURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty is allowed (uses default)", "", false},
		{"plain http", "http://127.0.0.1:11434", false},
		{"https", "https://ollama.internal:11434", false},
		{"missing scheme", "127.0.0.1:11434", true},
		{"file scheme", "file:///etc/passwd", true},
		{"gopher scheme", "gopher://evil/", true},
		{"userinfo present", "http://user:pass@127.0.0.1:11434", true},
		{"userinfo at-only", "http://@evil.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOllamaURL(c.url)
			if c.wantErr && err == nil {
				t.Fatalf("validateOllamaURL(%q) = nil, want error", c.url)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateOllamaURL(%q) = %v, want nil", c.url, err)
			}
		})
	}
}

// TestContainsShellMeta locks the shell-metacharacter detector used by the
// path classifier. Every character here is an injection vector if it
// reaches a shell; a miss is a bypass.
func TestContainsShellMeta(t *testing.T) {
	metas := []string{";", "&", "|", "$", "`", "\n", "\r", "\t", "<", ">", "\x00"}
	for _, m := range metas {
		if !containsShellMeta("safe"+m+"tail", false) {
			t.Errorf("containsShellMeta did not flag %q", m)
		}
	}
	if containsShellMeta("/var/log/app.log", false) {
		t.Error("containsShellMeta flagged a clean path")
	}
	// Backslash only counts when includeBackslash is set.
	if containsShellMeta(`a\b`, false) {
		t.Error("backslash flagged when includeBackslash=false")
	}
	if !containsShellMeta(`a\b`, true) {
		t.Error("backslash NOT flagged when includeBackslash=true")
	}
}

// TestCapWildcardCount bounds ** segments so a policy can't load an
// O(N^k) match prefix.
func TestCapWildcardCount(t *testing.T) {
	if err := capWildcardCount("/data/**/reports/*"); err != nil {
		t.Errorf("one ** should pass: %v", err)
	}
	if err := capWildcardCount("/**/a/**"); err != nil {
		t.Errorf("two ** should pass (at the cap): %v", err)
	}
	if err := capWildcardCount("/**/a/**/b/**"); err == nil {
		t.Error("three ** must be rejected")
	}
}

// TestAllReadOnlyKinds covers the SELECT-only helper that gates the
// MutatesViaCTE escalation.
func TestAllReadOnlyKinds(t *testing.T) {
	if !allReadOnlyKinds([]string{"SELECT", "select"}) {
		t.Error("all-SELECT should be read-only")
	}
	if allReadOnlyKinds([]string{"SELECT", "DELETE"}) {
		t.Error("a DELETE makes the set not read-only")
	}
	if !allReadOnlyKinds(nil) {
		t.Error("empty set is vacuously read-only")
	}
}

// TestInterpretClassifyResult covers the fail-closed decision mapping for
// the LLM content classifier without needing a live Ollama.
func TestInterpretClassifyResult(t *testing.T) {
	// Error → fail closed (fires).
	if fired, detail := interpretClassifyResult(nil, errors.New("timeout")); !fired || !strings.Contains(detail, "fail closed") {
		t.Errorf("error should fail closed, got fired=%v detail=%q", fired, detail)
	}
	// Nil result → fail closed.
	if fired, _ := interpretClassifyResult(nil, nil); !fired {
		t.Error("nil result should fail closed")
	}
	// "safe" → does not fire.
	if fired, detail := interpretClassifyResult(&llmguard.ClassifyResult{Category: "safe"}, nil); fired || detail != "" {
		t.Errorf("safe should not fire, got fired=%v detail=%q", fired, detail)
	}
	// Non-safe with reasoning → fires, reasoning surfaced.
	fired, detail := interpretClassifyResult(&llmguard.ClassifyResult{
		Category: "weapons", Confidence: 0.97, Reasoning: "requests a functional firearm schematic",
	}, nil)
	if !fired || !strings.Contains(detail, "weapons") || !strings.Contains(detail, "firearm") {
		t.Errorf("non-safe should fire with reasoning, got fired=%v detail=%q", fired, detail)
	}
	// Non-safe without reasoning → fires, no reason clause.
	fired, detail = interpretClassifyResult(&llmguard.ClassifyResult{Category: "csam", Confidence: 0.99}, nil)
	if !fired || !strings.Contains(detail, "csam") || strings.Contains(detail, "reason=") {
		t.Errorf("non-safe w/o reasoning, got fired=%v detail=%q", fired, detail)
	}
}
