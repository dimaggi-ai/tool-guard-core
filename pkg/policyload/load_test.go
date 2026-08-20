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

func TestLoadRejectsMultiDocumentYAML(t *testing.T) {
	_, err := loadText(t, "policy_id: shell\n---\npolicy_id: real\nscope:\n  tool_names: [run]\n")
	assertErrorContains(t, err, "exactly one YAML document")
}

func TestLoadAcceptsEmptyTrailingDocument(t *testing.T) {
	// A trailing bare `---` (or `--- # comment`) yields an empty second
	// document; 0.6.0 loaded such files and there is no content to lose.
	for _, text := range []string{
		"policy_id: test\nrules: []\n---\n",
		"policy_id: test\nrules: []\n---\n# trailing comment\n",
	} {
		if _, err := loadText(t, text); err != nil {
			t.Fatalf("empty trailing document must load, got: %v", err)
		}
	}
	// But a later document with content is still rejected.
	_, err := loadText(t, "policy_id: test\nrules: []\n---\n---\npolicy_id: real\n")
	assertErrorContains(t, err, "exactly one YAML document")
}

func TestLoadSchemaVersionTypeErrors(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantError string
	}{
		{name: "quoted", line: "schema_version: \"1\"\n", wantError: "must be an unquoted whole number"},
		{name: "boolean", line: "schema_version: yes\n", wantError: "must be an unquoted whole number"},
		{name: "fractional", line: "schema_version: 1.5\n", wantError: "must be an unquoted whole number"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadText(t, test.line+"policy_id: test\nrules: []\n")
			assertErrorContains(t, err, test.wantError)
		})
	}
	if _, err := loadText(t, "schema_version: 1.0\npolicy_id: test\nrules: []\n"); err != nil {
		t.Fatalf("whole-valued 1.0 must load: %v", err)
	}
}

func TestLoadFutureVersionWinsOverFieldGuidance(t *testing.T) {
	// A schema_version 2 file may legitimately contain fields v1 removed;
	// it must get the unsupported-version error, not v1 migration advice.
	_, err := loadText(t, "schema_version: 2\npolicy_id: test\ndeep_evaluation:\n  model: x\n")
	assertErrorContains(t, err, "unsupported schema_version 2")
}
