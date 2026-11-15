package policyload

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

func secretClassifyYAML(config string) string {
	return "policy_id: secret-test\nversion: 1\nrules:\n  - rule_id: secret-rule\n    effect: deny\n    conditions:\n      secret_classify:\n" + config
}

func TestLoadSecretClassify(t *testing.T) {
	policy, err := loadText(t, secretClassifyYAML("        field: parameters.content\n        classes: [provider, generic]\n        max_bytes: 65536\n        exclude_rules: [github-pat]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ValidatePolicy(&policy); err != nil {
		t.Fatal(err)
	}
	c := policy.Rules[0].Conditions.SecretClassify
	if c == nil || c.Field != "parameters.content" || len(c.Classes) != 2 || c.MaxBytes != 65536 || len(c.ExcludeRules) != 1 || c.ExcludeRules[0] != "github-pat" {
		t.Fatal("classifier config did not round trip")
	}
}

func TestLoadSecretClassifyRejectsUnknownFields(t *testing.T) {
	_, err := loadText(t, secretClassifyYAML("        field: parameters.content\n        classes: [provider]\n        max_byte: 65536\n"))
	assertErrorContains(t, err, "rules[0].conditions.secret_classify.max_byte")
}

func TestLoadSecretClassifyInvalidConfiguration(t *testing.T) {
	for _, tt := range []struct{ name, config, want string }{
		{"missing field", "classes: [provider]", "field is required"},
		{"missing classes", "field: parameters.content", "classes must contain"},
		{"unknown class", "field: parameters.content\nclasses: [unknown]", "unknown class"},
		{"duplicate class", "field: parameters.content\nclasses: [provider, provider]", "duplicate class"},
		{"negative cap", "field: parameters.content\nclasses: [provider]\nmax_bytes: -1", "max_bytes"},
		{"oversized cap", "field: parameters.content\nclasses: [provider]\nmax_bytes: 1048577", "max_bytes"},
		{"unknown exclusion", "field: parameters.content\nclasses: [provider]\nexclude_rules: [not-a-rule]", "unknown excluded rule"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := "        " + strings.ReplaceAll(tt.config, "\n", "\n        ") + "\n"
			policy, err := loadText(t, secretClassifyYAML(config))
			if err != nil {
				t.Fatalf("decode failed before semantic validation: %v", err)
			}
			assertErrorContains(t, engine.ValidatePolicy(&policy), tt.want)
		})
	}
}

func TestLoadSecretClassifyRejectsWrongTypes(t *testing.T) {
	for _, tt := range []struct{ name, config string }{
		{"classes scalar", "field: parameters.content\nclasses: provider"},
		{"field number", "field: 17\nclasses: [provider]"},
		{"fractional cap", "field: parameters.content\nclasses: [provider]\nmax_bytes: 1.5"},
		{"exclusion scalar", "field: parameters.content\nclasses: [provider]\nexclude_rules: github-pat"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadText(t, secretClassifyYAML("        "+strings.ReplaceAll(tt.config, "\n", "\n        ")+"\n"))
			if err == nil {
				t.Fatal("invalid YAML type accepted")
			}
		})
	}
}

func TestLoadSecretClassifyCannotBeNegated(t *testing.T) {
	text := "policy_id: secret-test\nversion: 1\nrules:\n  - rule_id: secret-rule\n    effect: deny\n    conditions:\n      not:\n        secret_classify:\n          field: parameters.content\n          classes: [provider]\n"
	policy, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	assertErrorContains(t, engine.ValidatePolicy(&policy), "may not appear under a not:")
}
