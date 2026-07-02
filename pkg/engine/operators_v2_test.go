package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// Tests for the v0.2.0 negative / presence operators. The most important
// property is the MISSING-FIELD contract: not_in / not_contains fail CLOSED
// (fire) so a deny rule using them cannot be dodged by omitting the field,
// while starts_with / ends_with / exists behave positively.

func leaf(field string, op domain.Operator, val interface{}) domain.Condition {
	return domain.Condition{Field: field, Operator: op, Value: val}
}

func TestOpNotIn(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]interface{}
		value  interface{}
		want   bool
	}{
		{"present-and-in-list-does-not-fire", map[string]interface{}{"tool_name": "read"}, []interface{}{"read", "list"}, false},
		{"present-and-not-in-list-fires", map[string]interface{}{"tool_name": "drop_tables"}, []interface{}{"read", "list"}, true},
		{"missing-field-fails-closed-fires", map[string]interface{}{}, []interface{}{"read", "list"}, true},
		{"numeric-in-list", map[string]interface{}{"amount": 3.0}, []interface{}{1.0, 2.0, 3.0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvalCondition(leaf("tool_name", domain.OpNotIn, tt.value), tt.fields)
			if tt.name == "numeric-in-list" {
				got = EvalCondition(leaf("amount", domain.OpNotIn, tt.value), tt.fields)
			}
			if got != tt.want {
				t.Errorf("not_in = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpNotContains(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]interface{}
		want   bool
	}{
		{"contains-does-not-fire", map[string]interface{}{"path": "/home/user/file"}, false},
		{"not-contains-fires", map[string]interface{}{"path": "/etc/passwd"}, true},
		{"missing-field-fails-closed", map[string]interface{}{}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := EvalCondition(leaf("path", domain.OpNotContains, "/home/"), tt.fields)
			if got != tt.want {
				t.Errorf("not_contains = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpStartsEndsWith(t *testing.T) {
	f := map[string]interface{}{"tool_name": "admin_delete_all", "path": "/etc/shadow"}
	if !EvalCondition(leaf("tool_name", domain.OpStartsWith, "admin_"), f) {
		t.Error("starts_with admin_ should fire")
	}
	if EvalCondition(leaf("tool_name", domain.OpStartsWith, "user_"), f) {
		t.Error("starts_with user_ should NOT fire")
	}
	if !EvalCondition(leaf("path", domain.OpEndsWith, "shadow"), f) {
		t.Error("ends_with shadow should fire")
	}
	if EvalCondition(leaf("path", domain.OpEndsWith, ".txt"), f) {
		t.Error("ends_with .txt should NOT fire")
	}
	// Positive operators do NOT fire on a missing field.
	if EvalCondition(leaf("missing", domain.OpStartsWith, "x"), f) {
		t.Error("starts_with on missing field must not fire")
	}
	if EvalCondition(leaf("missing", domain.OpEndsWith, "x"), f) {
		t.Error("ends_with on missing field must not fire")
	}
}

func TestOpExists(t *testing.T) {
	f := map[string]interface{}{"parameters.reason": "customer request"}
	// value=true → fire when present
	if !EvalCondition(leaf("parameters.reason", domain.OpExists, true), f) {
		t.Error("exists:true should fire when field present")
	}
	if EvalCondition(leaf("parameters.missing", domain.OpExists, true), f) {
		t.Error("exists:true should NOT fire when field absent")
	}
	// value=false → fire when absent (e.g. "deny if no justification given")
	if !EvalCondition(leaf("parameters.justification", domain.OpExists, false), f) {
		t.Error("exists:false should fire when field absent")
	}
	if EvalCondition(leaf("parameters.reason", domain.OpExists, false), f) {
		t.Error("exists:false should NOT fire when field present")
	}
	// no value → defaults to must-exist
	if !EvalCondition(leaf("parameters.reason", domain.OpExists, nil), f) {
		t.Error("exists with no value defaults to must-exist and should fire when present")
	}
}

// A realistic composite: deny a shell tool call whose tool_name is NOT in the
// approved set — the exact tool-substitution bypass class, expressed without
// regex. Verifies the operators compose inside an AND tree.
func TestOpNotIn_ToolSubstitutionGuard(t *testing.T) {
	cond := domain.Condition{
		And: []domain.Condition{
			leaf("tool_group", domain.OpEq, "shell"),
			leaf("tool_name", domain.OpNotIn, []interface{}{"run_tests", "build"}),
		},
	}
	deny := map[string]interface{}{"tool_group": "shell", "tool_name": "rm_rf_slash"}
	allow := map[string]interface{}{"tool_group": "shell", "tool_name": "run_tests"}
	if !EvalCondition(cond, deny) {
		t.Error("unapproved shell tool should fire the deny rule")
	}
	if EvalCondition(cond, allow) {
		t.Error("approved shell tool should not fire")
	}
}
