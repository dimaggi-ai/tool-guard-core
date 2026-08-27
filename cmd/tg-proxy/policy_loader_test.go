package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const duplicateIdentityPolicy = `policy_id: shared-id
name: duplicate identity
version: 4
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
rules:
  - rule_id: %s
    name: test rule
    conditions: {field: amount, operator: gt, value: 0}
    effect: deny
    citation: {document_id: D, excerpt: X}
`

func TestProxyReloadRejectsDuplicatePolicyIdentity(t *testing.T) {
	dir := t.TempDir()
	for name, ruleID := range map[string]string{"first.yaml": "first", "second.yaml": "second"} {
		contents := strings.Replace(duplicateIdentityPolicy, "%s", ruleID, 1)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	p := &proxy{policyDir: dir}
	err := p.reload()
	if err == nil || !strings.Contains(err.Error(), "duplicate policy identity") {
		t.Fatalf("reload duplicate-identity error = %v", err)
	}
	if got := p.policyCount(); got != 0 {
		t.Fatalf("failed reload installed %d policies", got)
	}
}

func TestProxyReloadRejectsDuplicateRuleID(t *testing.T) {
	dir := t.TempDir()
	policy := strings.Replace(duplicateIdentityPolicy, "%s", "same", 1)
	policy = strings.Replace(policy, "    citation: {document_id: D, excerpt: X}\n", `    citation: {document_id: D, excerpt: X}
  - rule_id: same
    name: duplicate rule
    conditions: {field: amount, operator: gt, value: 1}
    effect: escalate
    citation: {document_id: D, excerpt: Y}
`, 1)
	if err := os.WriteFile(filepath.Join(dir, "duplicate-rules.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &proxy{policyDir: dir}
	err := p.reload()
	if err == nil || !strings.Contains(err.Error(), "duplicate rule_id") {
		t.Fatalf("reload duplicate-rule error = %v", err)
	}
}
