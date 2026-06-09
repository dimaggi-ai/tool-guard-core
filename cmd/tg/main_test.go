package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestLint_AcceptsAllKnownOperators pins the contract that the
// unknown-operator allowlist must include EVERY operator the engine
// actually implements; otherwise a valid policy using e.g. gt_field
// would lint as error and exit 6. An earlier version of knownOperators
// was missing gt_field and lt_field — this test would have failed
// against it.
func TestLint_AcceptsAllKnownOperators(t *testing.T) {
	operators := []domain.Operator{
		domain.OpEq, domain.OpNeq,
		domain.OpGt, domain.OpGte, domain.OpLt, domain.OpLte,
		domain.OpIn, domain.OpContains, domain.OpRegex,
		domain.OpGtField, domain.OpLtField,
	}
	for _, op := range operators {
		t.Run(string(op), func(t *testing.T) {
			p := domain.Policy{
				Scope: domain.PolicyScope{
					ToolNames:  []string{"issue_refund"},
					ToolGroups: []string{"monetary_outflow"},
				},
				Rules: []domain.Rule{
					{
						RuleID: "r-known-op",
						Conditions: domain.Condition{
							Field:    "amount",
							Operator: op,
							Value:    float64(1),
						},
						Effect: domain.EffectDeny,
						Citation: domain.Citation{
							DocumentID: "d",
							Excerpt:    "x",
						},
					},
				},
			}
			findings := lintPolicy(p)
			for _, f := range findings {
				if f.Rule == "unknown-operator" {
					t.Errorf("operator %q (valid in engine) tripped unknown-operator lint: %+v", op, f)
				}
			}
		})
	}
}

// TestLint_FlagsUnknownOperator confirms the positive case still works:
// an operator the engine does not implement gets the error finding.
func TestLint_FlagsUnknownOperator(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames:  []string{"issue_refund"},
			ToolGroups: []string{"monetary_outflow"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "r-typo",
				Conditions: domain.Condition{
					Field:    "amount",
					Operator: "greater_than",
					Value:    float64(500),
				},
				Effect:   domain.EffectDeny,
				Citation: domain.Citation{DocumentID: "d", Excerpt: "x"},
			},
		},
	}
	hit := false
	for _, f := range lintPolicy(p) {
		if f.Rule == "unknown-operator" && f.Severity == "error" {
			hit = true
		}
	}
	if !hit {
		t.Error("expected unknown-operator error finding for typo'd 'greater_than'")
	}
}

// TestLint_AllDomainOperatorsRegistered guarantees that every Operator constant
// defined in pkg/domain/policy.go is registered in knownOperators map in main.go,
// preventing future developers from adding a new operator without registering it.
func TestLint_AllDomainOperatorsRegistered(t *testing.T) {
	fset := token.NewFileSet()
	path := filepath.Join("..", "..", "pkg", "domain", "policy.go")
	node, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse policy.go: %v", err)
	}

	foundOperators := make(map[string]bool)

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		var currentType string
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if valueSpec.Type != nil {
				if ident, ok := valueSpec.Type.(*ast.Ident); ok {
					currentType = ident.Name
				} else {
					currentType = ""
				}
			}
			if currentType != "Operator" {
				continue
			}
			for i, name := range valueSpec.Names {
				_ = name
				if i < len(valueSpec.Values) {
					lit, ok := valueSpec.Values[i].(*ast.BasicLit)
					if ok && lit.Kind == token.STRING {
						val := lit.Value
						if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
							val = val[1 : len(val)-1]
						}
						foundOperators[val] = true
					}
				}
			}
		}
	}

	if len(foundOperators) == 0 {
		t.Fatal("found zero Operator constants in policy.go; parser logic might be broken")
	}

	for op := range foundOperators {
		if _, ok := knownOperators[op]; !ok {
			t.Errorf("operator %q is defined in policy.go but missing from knownOperators map in main.go", op)
		}
	}
}


func TestLintPolicy_RuleIdCollision(t *testing.T) {
	p := domain.Policy{
		Scope: domain.PolicyScope{
			ToolNames:  []string{"issue_refund"},
			ToolGroups: []string{"monetary_outflow"},
		},
		Rules: []domain.Rule{
			{
				RuleID: "dup-id",
				Conditions: domain.Condition{
					Field:    "amount",
					Operator: domain.OpGt,
					Value:    float64(500),
				},
				Citation: domain.Citation{DocumentID: "doc-1", Excerpt: "refund cap"},
			},
			{
				RuleID: "dup-id",
				Conditions: domain.Condition{
					Field:    "amount",
					Operator: domain.OpGt,
					Value:    float64(1000),
				},
				Citation: domain.Citation{DocumentID: "doc-1", Excerpt: "supervisor refund cap"},
			},
		},
	}

	findings := lintPolicy(p)
	foundCollision := false
	for _, f := range findings {
		if f.Rule == "rule-id-collision" {
			foundCollision = true
			if f.Severity != "error" {
				t.Errorf("expected error severity for rule-id-collision, got %s", f.Severity)
			}
		}
	}
	if !foundCollision {
		t.Error("expected rule-id-collision warning/error, but none was found")
	}
}

func TestLintPolicy_InvalidRegexSyntax(t *testing.T) {
	tests := []struct {
		name      string
		condition domain.Condition
		wantBad   bool
	}{
		{
			name: "valid regex in leaf",
			condition: domain.Condition{
				Field:    "reason",
				Operator: domain.OpRegex,
				Value:    "^[a-zA-Z]+$",
			},
			wantBad: false,
		},
		{
			name: "invalid regex in leaf",
			condition: domain.Condition{
				Field:    "reason",
				Operator: domain.OpRegex,
				Value:    "[unclosed",
			},
			wantBad: true,
		},
		{
			name: "invalid regex in And branch",
			condition: domain.Condition{
				And: []domain.Condition{
					{
						Field:    "reason",
						Operator: domain.OpRegex,
						Value:    "[unclosed",
					},
				},
			},
			wantBad: true,
		},
		{
			name: "invalid regex in Or branch",
			condition: domain.Condition{
				Or: []domain.Condition{
					{
						Field:    "reason",
						Operator: domain.OpRegex,
						Value:    "[unclosed",
					},
				},
			},
			wantBad: true,
		},
		{
			name: "invalid regex in Not branch",
			condition: domain.Condition{
				Not: &domain.Condition{
					Field:    "reason",
					Operator: domain.OpRegex,
					Value:    "[unclosed",
				},
			},
			wantBad: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := domain.Policy{
				Scope: domain.PolicyScope{
					ToolNames:  []string{"issue_refund"},
					ToolGroups: []string{"monetary_outflow"},
				},
				Rules: []domain.Rule{
					{
						RuleID:     "r-test",
						Conditions: tc.condition,
						Citation:   domain.Citation{DocumentID: "doc-1", Excerpt: "something"},
					},
				},
			}

			findings := lintPolicy(p)
			foundRegexError := false
			for _, f := range findings {
				if f.Rule == "invalid-regex-syntax" {
					foundRegexError = true
					if f.Severity != "error" {
						t.Errorf("expected error severity for invalid-regex-syntax, got %s", f.Severity)
					}
				}
			}
			if foundRegexError != tc.wantBad {
				t.Errorf("got invalid-regex-syntax finding = %v, want %v", foundRegexError, tc.wantBad)
			}
		})
	}
}

func TestCmdEvaluate_ExitCodes(t *testing.T) {
	// Write a shadow policy to temp file
	tmpDir := t.TempDir()
	shadowPolicyPath := filepath.Join(tmpDir, "shadow_policy.yaml")
	shadowPolicyYAML := `policy_id: pol-shadow-refund
name: shadow-refund-cap
version: 1
status: approved
mode: shadow
scope:
  tool_names:
    - issue_refund
rules:
  - rule_id: rule-amount-cap
    conditions:
      field: amount
      operator: gt
      value: 500
    effect: deny
    citation:
      document_id: doc-refund-sop
      excerpt: "Limit"
`
	if err := os.WriteFile(shadowPolicyPath, []byte(shadowPolicyYAML), 0644); err != nil {
		t.Fatalf("failed to write shadow policy: %v", err)
	}

	enforcementPolicyPath := filepath.Join(tmpDir, "enforcement_policy.yaml")
	enforcementPolicyYAML := `policy_id: pol-enforce-refund
name: enforce-refund-cap
version: 1
status: approved
mode: enforcement
scope:
  tool_names:
    - issue_refund
rules:
  - rule_id: rule-amount-cap
    conditions:
      field: amount
      operator: gt
      value: 500
    effect: deny
    citation:
      document_id: doc-refund-sop
      excerpt: "Limit"
`
	if err := os.WriteFile(enforcementPolicyPath, []byte(enforcementPolicyYAML), 0644); err != nil {
		t.Fatalf("failed to write enforcement policy: %v", err)
	}

	callPath := filepath.Join(tmpDir, "call_over_cap.json")
	callJSON := `{"tool_name": "issue_refund", "parameters": {"amount": 1000}}`
	if err := os.WriteFile(callPath, []byte(callJSON), 0644); err != nil {
		t.Fatalf("failed to write call JSON: %v", err)
	}

	// Redirect stdout to avoid polluting test logs
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()
	nullFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stdout = nullFile
		defer nullFile.Close()
	}

	// 1. Enforcement mode: should exit with 3 (denied)
	code := cmdEvaluate([]string{"-policy", enforcementPolicyPath, "-call", callPath, "-mode", "enforcement"})
	if code != 3 {
		t.Errorf("expected exit code 3 in enforcement mode, got %d", code)
	}

	// 2. Shadow mode (policy=shadow, CLI=shadow): should exit with 0 (allowed)
	code = cmdEvaluate([]string{"-policy", shadowPolicyPath, "-call", callPath, "-mode", "shadow"})
	if code != 0 {
		t.Errorf("expected exit code 0 in shadow mode, got %d", code)
	}
}
