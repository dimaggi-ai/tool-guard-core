package policyload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestPolicySetHashIsOrderIndependentAndContentSensitive(t *testing.T) {
	a := domain.Policy{
		SchemaVersion: 1,
		PolicyID:      "alpha",
		Version:       1,
		Status:        domain.PolicyStatusApproved,
		Mode:          domain.PolicyModeEnforcement,
		Compliance:    map[string][]string{"soc2": {"cc6.1", "cc7.2"}},
	}
	b := domain.Policy{
		SchemaVersion: 1,
		PolicyID:      "beta",
		Version:       3,
		Status:        domain.PolicyStatusApproved,
		Mode:          domain.PolicyModeShadow,
	}

	forward, err := PolicySetHash([]domain.Policy{a, b})
	if err != nil {
		t.Fatalf("PolicySetHash(forward): %v", err)
	}
	reverse, err := PolicySetHash([]domain.Policy{b, a})
	if err != nil {
		t.Fatalf("PolicySetHash(reverse): %v", err)
	}
	if forward != reverse {
		t.Fatalf("policy order changed hash: forward=%q reverse=%q", forward, reverse)
	}
	if !strings.HasPrefix(forward, "sha256:") || len(forward) != len("sha256:")+64 {
		t.Fatalf("hash = %q, want sha256:<64 lowercase hex chars>", forward)
	}

	b.Version++
	changed, err := PolicySetHash([]domain.Policy{a, b})
	if err != nil {
		t.Fatalf("PolicySetHash(changed): %v", err)
	}
	if changed == forward {
		t.Fatal("policy content change did not change hash")
	}
}

func TestPolicySetHashIgnoresYAMLPresentation(t *testing.T) {
	dir := t.TempDir()
	compact := filepath.Join(dir, "compact.yaml")
	commented := filepath.Join(dir, "commented.yaml")
	if err := os.WriteFile(compact, []byte(`schema_version: 1
policy_id: same-policy
name: Same policy
version: 1
status: approved
mode: enforcement
scope: {tool_names: [read]}
rules: []
`), 0o600); err != nil {
		t.Fatalf("write compact policy: %v", err)
	}
	if err := os.WriteFile(commented, []byte(`# presentation-only changes do not alter the loaded object
schema_version: 1
policy_id: same-policy
name: Same policy
version: 1
status: approved
mode: enforcement
scope:
  tool_names:
    - read
rules: [] # same empty rule list
`), 0o600); err != nil {
		t.Fatalf("write commented policy: %v", err)
	}

	first, err := Load(compact)
	if err != nil {
		t.Fatalf("Load(compact): %v", err)
	}
	second, err := Load(commented)
	if err != nil {
		t.Fatalf("Load(commented): %v", err)
	}
	firstHash, err := PolicySetHash([]domain.Policy{first})
	if err != nil {
		t.Fatalf("PolicySetHash(compact): %v", err)
	}
	secondHash, err := PolicySetHash([]domain.Policy{second})
	if err != nil {
		t.Fatalf("PolicySetHash(commented): %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("YAML presentation changed hash: %q != %q", firstHash, secondHash)
	}
}

func TestPolicySetHashEmptySetIsDeterministic(t *testing.T) {
	nilHash, err := PolicySetHash(nil)
	if err != nil {
		t.Fatalf("PolicySetHash(nil): %v", err)
	}
	emptyHash, err := PolicySetHash([]domain.Policy{})
	if err != nil {
		t.Fatalf("PolicySetHash(empty): %v", err)
	}
	if nilHash != emptyHash {
		t.Fatalf("nil and empty sets differ: %q != %q", nilHash, emptyHash)
	}
}
