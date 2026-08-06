package policyload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestLoadSchemaVersion(t *testing.T) {
	tests := []struct {
		name        string
		versionLine string
		wantVersion int
		wantError   string
	}{
		{name: "absent is version one", wantVersion: 1},
		{name: "version one", versionLine: "schema_version: 1\n", wantVersion: 1},
		{name: "version two", versionLine: "schema_version: 2\n", wantError: "unsupported schema_version 2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := loadText(t, test.versionLine+"policy_id: test\nrules: []\n")
			if test.wantError != "" {
				assertErrorContains(t, err, test.wantError)
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if policy.SchemaVersion != test.wantVersion {
				t.Fatalf("SchemaVersion = %d, want %d", policy.SchemaVersion, test.wantVersion)
			}
		})
	}
}

func TestLoadRejectsUnknownFieldsWithPaths(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		wantError string
	}{
		{
			name:      "top level",
			policy:    "policy_id: test\nunknown_top: true\n",
			wantError: `unknown field "unknown_top" at unknown_top`,
		},
		{
			name:      "scope",
			policy:    "policy_id: test\nscope:\n  tool_namse: [run]\n",
			wantError: `unknown field "tool_namse" at scope.tool_namse`,
		},
		{
			name:      "condition",
			policy:    "policy_id: test\nrules:\n  - conditions:\n      operatr: eq\n",
			wantError: `unknown field "operatr" at rules[0].conditions.operatr`,
		},
		{
			name:      "classifier config",
			policy:    "policy_id: test\nrules:\n  - conditions:\n      llm_classify:\n        prompt_feld: parameters.prompt\n",
			wantError: `unknown field "prompt_feld" at rules[0].conditions.llm_classify.prompt_feld`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadText(t, test.policy)
			assertErrorContains(t, err, test.wantError)
		})
	}
}

func TestLoadRejectsMisspelledScopeInsteadOfMakingPolicyGlobal(t *testing.T) {
	_, err := loadText(t, "policy_id: test\nscpoe:\n  tool_names: [run]\n")
	assertErrorContains(t, err, `unknown field "scpoe" at scpoe`)
}

func TestLoadRejectsRemovedDeepEvaluationWithMigration(t *testing.T) {
	_, err := loadText(t, "policy_id: test\ndeep_evaluation:\n  model: gemma4:e4b\n")
	assertErrorContains(t, err, `field "deep_evaluation" was removed`)
	assertErrorContains(t, err, `"llm_classify" condition`)
}

func loadText(t *testing.T, policy string) (domain.Policy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
