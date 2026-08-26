package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
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
		pol, err := policyload.Load(full)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := engine.ValidatePolicy(&pol); err != nil {
			return fmt.Errorf("%s: validate: %w", name, err)
		}
		loaded = append(loaded, pol)
	}
	if err := engine.ValidatePolicySet(loaded); err != nil {
		return fmt.Errorf("validate policy set: %w", err)
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
