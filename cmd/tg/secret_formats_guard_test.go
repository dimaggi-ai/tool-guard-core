package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// The generated regex layer has been replaced by typed classifier leaves.
// Every optional field must retain its existence guard: absent edit fields
// otherwise trigger the classifier's fail-closed behavior.
func TestSecretFormatGuards(t *testing.T) {
	policy := loadSecretCommandsPolicy(t)
	counts := map[string]int{}
	var visit func(domain.Condition)
	visit = func(c domain.Condition) {
		if len(c.And) == 2 && c.And[1].SecretClassify != nil {
			classifier := c.And[1].SecretClassify
			guard := c.And[0]
			if guard.Field != classifier.Field || guard.Operator != domain.OpExists || guard.Value != true {
				t.Errorf("classifier %s lacks its presence guard", classifier.Field)
			}
			if len(classifier.Classes) == 1 && classifier.Classes[0] == "provider" {
				counts[classifier.Field]++
			}
			return
		}
		if c.SecretClassify != nil {
			t.Error("unguarded classifier")
		}
		for _, child := range c.And {
			visit(child)
		}
		for _, child := range c.Or {
			visit(child)
		}
	}
	for _, rule := range policy.Rules {
		visit(rule.Conditions)
	}
	for field, want := range map[string]int{"parameters.command": 1, "parameters.content": 2, "parameters.new_string": 2, "parameters.edits": 2} {
		if counts[field] != want {
			t.Errorf("%s: got %d classifier leaves, want %d", field, counts[field], want)
		}
	}
}

func TestSecretCommandsTruncationDiagnostic(t *testing.T) {
	policy := loadSecretCommandsPolicy(t)
	// This format belongs to the typed layer, not the hand-written patterns.
	token := "glrt-" + "7Qm4Zv8Lr2Px6Nb9Yk3J"
	params, err := json.Marshal(map[string]string{"file_path": "/project/NOTES.md", "content": strings.Repeat(" ", 65536) + token})
	if err != nil {
		t.Fatal(err)
	}
	envelope := domain.ActionEnvelope{ToolName: "write", ToolGroup: "filesystem_writes", Parameters: params}
	result := engine.NewEvaluator().Evaluate(&envelope, []domain.Policy{policy}, domain.PolicyModeEnforcement)
	for _, rule := range result.RuleResults {
		if rule.RuleID == "rule-secret-in-agent-note" {
			if rule.Matched || !strings.Contains(rule.Details, "truncated=true") || !strings.Contains(rule.Details, "scanned_bytes=65536") {
				t.Fatalf("truncated clean prefix lost its scan metadata: matched=%t detail=%s", rule.Matched, rule.Details)
			}
			return
		}
	}
	t.Fatal("note rule was not evaluated")
}
