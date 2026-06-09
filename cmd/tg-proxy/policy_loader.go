package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"gopkg.in/yaml.v3"
)

// ── policy loading ─────────────────────────────────────────────────────────
// Reads YAML files from policyDir, validates them via engine.ValidatePolicy
// (which refuses empty conditions, bad regex, type-mismatched operators,
// and over-deep glob patterns), and atomically swaps the policy set.

func (p *proxy) reload() error {
	entries, err := os.ReadDir(p.policyDir)
	if err != nil {
		return fmt.Errorf("read policy dir: %w", err)
	}
	loaded := make([]domain.Policy, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			continue
		}
		full := filepath.Join(p.policyDir, name)
		pol, err := loadPolicyYAML(full)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := engine.ValidatePolicy(&pol); err != nil {
			return fmt.Errorf("%s: validate: %w", name, err)
		}
		loaded = append(loaded, pol)
	}
	// Pre-warm the regex compile cache so the first /evaluate call
	// for any newly-loaded policy doesn't pay compile latency. This
	// also surfaces a regex that ValidatePolicy accepted but Go's
	// regexp.Compile would have rejected (shouldn't happen — they
	// share the same engine — but defence in depth).
	engine.PrewarmRegexCache(loaded)

	p.mu.Lock()
	p.policies = loaded
	p.mu.Unlock()
	p.loadCount.Add(1)
	return nil
}

func (p *proxy) policyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.policies)
}

// loadPolicyYAML mirrors the YAML→JSON shim used by `tg lint` so domain
// types stay JSON-only.
func loadPolicyYAML(path string) (domain.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return domain.Policy{}, err
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return domain.Policy{}, fmt.Errorf("parse YAML: %w", err)
	}
	raw = normalizeYAML(raw)
	js, err := json.Marshal(raw)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("yaml→json: %w", err)
	}
	var pol domain.Policy
	if err := json.Unmarshal(js, &pol); err != nil {
		return domain.Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if pol.Status == "" {
		pol.Status = domain.PolicyStatusApproved
	}
	if pol.Mode == "" {
		pol.Mode = domain.PolicyModeEnforcement
	}
	// A misspelled status/mode must not silently demote enforcement or
	// approval gating — refuse to load.
	switch pol.Status {
	case domain.PolicyStatusDraft, domain.PolicyStatusReview, domain.PolicyStatusApproved, domain.PolicyStatusArchived:
	default:
		return domain.Policy{}, fmt.Errorf("policy %q: unknown status %q (must be draft|review|approved|archived)", pol.PolicyID, pol.Status)
	}
	switch pol.Mode {
	case domain.PolicyModeShadow, domain.PolicyModeEnforcement:
	default:
		return domain.Policy{}, fmt.Errorf("policy %q: unknown mode %q (must be shadow|enforcement)", pol.PolicyID, pol.Mode)
	}
	return pol, nil
}

// normalizeYAML rewrites yaml.v3's map[interface{}]interface{} output
// into map[string]interface{} so encoding/json can marshal it. Visits
// nested structures recursively.
func normalizeYAML(v any) any {
	switch m := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = normalizeYAML(val)
		}
		return out
	case map[string]any:
		for k, val := range m {
			m[k] = normalizeYAML(val)
		}
		return m
	case []any:
		for i, x := range m {
			m[i] = normalizeYAML(x)
		}
		return m
	default:
		return v
	}
}
