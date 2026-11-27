package mainfloor

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestMergedClassifiersValidation(t *testing.T) {
	command := domain.Condition{CommandClassify: &domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}}
	secret := domain.Condition{SecretClassify: secretTestConfig("provider")}
	for _, condition := range []domain.Condition{command, secret} {
		if !condition.IsLeaf() {
			t.Fatal("classifier is not a leaf")
		}
		if err := validateCondition(&condition, "merged", 0, false); err != nil {
			t.Fatal(err)
		}
		negated := domain.Condition{Not: &domain.Condition{And: []domain.Condition{condition}}}
		err := validateCondition(&negated, "merged", 0, false)
		if err == nil || !strings.Contains(err.Error(), "command_classify") || !strings.Contains(err.Error(), "secret_classify") {
			t.Fatalf("negated classifier must reject with both classifier names: %v", err)
		}
	}
	for _, condition := range []domain.Condition{{}, {CommandClassify: command.CommandClassify, SecretClassify: secret.SecretClassify}} {
		err := validateCondition(&condition, "merged", 0, false)
		if err == nil || !strings.Contains(err.Error(), "command_classify") || !strings.Contains(err.Error(), "secret_classify") {
			t.Fatalf("invalid classifier node: %v", err)
		}
	}
}
