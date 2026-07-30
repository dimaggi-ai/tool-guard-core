package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite" // register SQL dialects
	"gopkg.in/yaml.v3"
)

// envFor builds a minimal envelope for a tool call with the given parameters.
func envFor(tool, group string, params map[string]any) domain.ActionEnvelope {
	var raw json.RawMessage
	if params != nil {
		b, _ := json.Marshal(params)
		raw = b
	}
	return domain.ActionEnvelope{
		EnvelopeID: "env-rev",
		Timestamp:  time.Now().UTC(),
		ToolName:   tool,
		ToolGroup:  group,
		Parameters: raw,
	}
}

func TestClassifyReversibility(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		group  string
		params map[string]any
		want   ReversibilityClass
	}{
		// ── Reversible: reads and trivially-undoable actions ──
		{"read tool", "read_file", "filesystem", nil, Reversible},
		{"list tool", "list_orders", "orders", nil, Reversible},
		{"get tool", "get_ticker", "market_data", nil, Reversible},
		{"add-label", "add_label", "gmail", nil, Reversible},
		{"create-draft", "create_draft", "gmail", nil, Reversible},
		{"camelCase get wins over object noun", "getRefundStatus", "", nil, Reversible},

		// ── Recoverable: undoable with effort ──
		{"update verb", "update_record", "crm", nil, Recoverable},
		{"edit verb", "edit_document", "docs", nil, Recoverable},
		{"filesystem_writes group", "write_file", "filesystem_writes", nil, Recoverable},

		// ── Irreversible: tool-group / tool-name signals ──
		{"payments group", "charge_card", "payments", nil, Irreversible},
		{"monetary_outflow group (refund demo)", "issue_refund", "monetary_outflow", nil, Irreversible},
		{"wire transfer name", "wire_transfer", "", nil, Irreversible},
		{"transfer verb", "transfer_funds", "", nil, Irreversible},
		{"payout noun anywhere", "process_payout", "", nil, Irreversible},
		{"deploy verb", "deploy_service", "", nil, Irreversible},
		{"publish verb", "publish_release", "", nil, Irreversible},
		{"physical actuation verb", "actuate_valve", "", nil, Irreversible},
		{"physical actuation group", "open", "physical_actuation", nil, Irreversible},
		{"send (irrevocable comms)", "send_email", "gmail", nil, Irreversible},
		{"delete-account exact name", "delete_account", "", nil, Irreversible},
		{"drop-database exact name", "dropDatabase", "", nil, Irreversible},

		// ── Irreversible: destructive SQL ──
		{"SQL DROP", "run_sql", "", map[string]any{"sql": "DROP TABLE users"}, Irreversible},
		{"SQL TRUNCATE", "run_sql", "", map[string]any{"sql": "TRUNCATE TABLE audit"}, Irreversible},
		{"SQL DELETE without WHERE", "run_sql", "", map[string]any{"sql": "DELETE FROM users"}, Irreversible},
		{"SQL DELETE with WHERE is Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE id = 1"}, Recoverable},
		{"SQL UPDATE is Recoverable", "run_sql", "", map[string]any{"sql": "UPDATE users SET name = 'x' WHERE id = 1"}, Recoverable},
		{"SQL SELECT is Reversible", "run_sql", "", map[string]any{"sql": "SELECT * FROM users"}, Reversible},

		// ── Destructive shell ──
		{"shell rm -rf", "bash", "", map[string]any{"command": "rm -rf /data"}, Irreversible},
		{"shell rm single file is Recoverable", "bash", "", map[string]any{"command": "rm /tmp/file.txt"}, Recoverable},
		{"shell shred", "bash", "", map[string]any{"command": "shred -u secret.key"}, Irreversible},
		{"shell mkfs", "bash", "", map[string]any{"command": "mkfs.ext4 /dev/sdb"}, Irreversible},
		{"shell read-only ls", "bash", "", map[string]any{"command": "ls -la /tmp"}, Reversible},
		{"shell worst-of-segments", "bash", "", map[string]any{"command": "ls /etc && rm -rf /data"}, Irreversible},
		{"argv rm -rf", "shell", "", map[string]any{"argv": []any{"rm", "-rf", "/data"}}, Irreversible},

		// ── HTTP method ──
		{"HTTP GET", "http_request", "", map[string]any{"url": "https://api.example.com/x", "method": "GET"}, Reversible},
		{"HTTP DELETE is Recoverable", "http_request", "", map[string]any{"url": "https://api.example.com/x/1", "method": "DELETE"}, Recoverable},
		{"HTTP POST is Recoverable", "http_request", "", map[string]any{"url": "https://api.example.com/x", "method": "POST"}, Recoverable},

		// ── Unknown default (fail-safe) ──
		{"unrecognized tool", "frobnicate_widget", "misc", nil, Unknown},
		{"empty envelope", "", "", nil, Unknown},
		{"unknown shell prog stays Unknown", "bash", "", map[string]any{"command": "customtool --go"}, Unknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyReversibility(envFor(tc.tool, tc.group, tc.params))
			if got != tc.want {
				t.Errorf("ClassifyReversibility(tool=%q, group=%q, params=%v) = %q, want %q",
					tc.tool, tc.group, tc.params, got, tc.want)
			}
		})
	}
}

// TestSQLKeywordFallback pins the dialect-free path directly, so the
// destructive-SQL mapping is covered even in a deployment where no sqlguard
// parser is linked into the binary.
func TestSQLKeywordFallback(t *testing.T) {
	cases := []struct {
		sql  string
		want ReversibilityClass
	}{
		{"DROP TABLE users", Irreversible},
		{"truncate table audit", Irreversible},
		{"DELETE FROM users", Irreversible},
		{"DELETE FROM users WHERE id = 1", Recoverable},
		{"UPDATE users SET x = 1", Recoverable},
		{"INSERT INTO users VALUES (1)", Recoverable},
		{"SELECT * FROM users", Reversible},
		{"EXPLAIN ANALYZE foo", Unknown},
		{"", Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			if got := sqlKeywordFallback(tc.sql); got != tc.want {
				t.Errorf("sqlKeywordFallback(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}

// TestHasSQLWord confirms whole-word matching (no substring false positives).
func TestHasSQLWord(t *testing.T) {
	if hasSQLWord("SELECT elsewhere FROM t", "WHERE") {
		t.Error("hasSQLWord matched WHERE inside the column name 'elsewhere'")
	}
	if !hasSQLWord("delete from t where id=1", "WHERE") {
		t.Error("hasSQLWord failed to match a real WHERE clause")
	}
}

func TestHasRecursiveFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-rf", "/x"}, true},
		{[]string{"-fr", "/x"}, true},
		{[]string{"-R", "/x"}, true},
		{[]string{"--recursive", "/x"}, true},
		{[]string{"-f", "/x"}, false},
		{[]string{"/x"}, false},
		{[]string{"--force", "/x"}, false},
	}
	for _, tc := range cases {
		if got := hasRecursiveFlag(tc.args); got != tc.want {
			t.Errorf("hasRecursiveFlag(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestReversibilityFieldExposed proves the class is available to rule
// conditions as the flattened "reversibility" field.
func TestReversibilityFieldExposed(t *testing.T) {
	env := envFor("wire_transfer", "payments", nil)
	fields := FlattenEnvelope(&env)
	if got := fields["reversibility"]; got != "irreversible" {
		t.Fatalf("fields[\"reversibility\"] = %v, want \"irreversible\"", got)
	}
	// And it must be matchable with a normal leaf condition.
	cond := domain.Condition{Field: "reversibility", Operator: domain.OpEq, Value: "irreversible"}
	if !EvalCondition(cond, fields) {
		t.Error("expected {field: reversibility, eq, irreversible} to match")
	}
}

// loadYAMLPolicy loads a shipped YAML policy the same way the proxy loader
// does (YAML → JSON → domain.Policy), so the engine test exercises the real
// on-disk policy file.
func loadYAMLPolicy(t *testing.T, path string) domain.Policy {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy %s: %v", path, err)
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse YAML %s: %v", path, err)
	}
	js, err := json.Marshal(normalizeYAMLTest(raw))
	if err != nil {
		t.Fatalf("yaml→json %s: %v", path, err)
	}
	var pol domain.Policy
	if err := json.Unmarshal(js, &pol); err != nil {
		t.Fatalf("decode policy %s: %v", path, err)
	}
	return pol
}

// normalizeYAMLTest rewrites any map[any]any nodes into map[string]any so
// encoding/json can marshal the parsed YAML (mirrors the proxy loader).
func normalizeYAMLTest(v any) any {
	switch m := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = normalizeYAMLTest(val)
		}
		return out
	case map[string]any:
		for k, val := range m {
			m[k] = normalizeYAMLTest(val)
		}
		return m
	case []any:
		for i, x := range m {
			m[i] = normalizeYAMLTest(x)
		}
		return m
	default:
		return v
	}
}

// TestIrreversibilityFloorPolicy is the evaluator-level integration test: it
// loads the shipped policies/irreversibility_floor.yaml and proves an
// irreversible action escalates while a reversible one is allowed.
func TestIrreversibilityFloorPolicy(t *testing.T) {
	policy := loadYAMLPolicy(t, filepath.Join("..", "..", "policies", "irreversibility_floor.yaml"))
	if err := ValidatePolicy(&policy); err != nil {
		t.Fatalf("shipped policy failed validation: %v", err)
	}
	if policy.Status != domain.PolicyStatusApproved {
		t.Fatalf("policy status = %q, want approved (so it is actually enforced)", policy.Status)
	}

	cases := []struct {
		name   string
		tool   string
		group  string
		params map[string]any
		want   domain.Decision
	}{
		{"wire transfer escalates", "wire_transfer", "payments", nil, domain.DecisionEscalated},
		{"refund escalates", "issue_refund", "monetary_outflow", map[string]any{"amount": 20}, domain.DecisionEscalated},
		{"DROP TABLE escalates", "run_sql", "", map[string]any{"sql": "DROP TABLE users"}, domain.DecisionEscalated},
		{"rm -rf escalates", "bash", "", map[string]any{"command": "rm -rf /data"}, domain.DecisionEscalated},
		{"read is allowed", "get_ticker", "market_data", nil, domain.DecisionAllowed},
		{"add-label is allowed", "add_label", "gmail", nil, domain.DecisionAllowed},
	}

	eval := NewEvaluator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := envFor(tc.tool, tc.group, tc.params)
			result := eval.Evaluate(&env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
			if result.Decision != tc.want {
				t.Fatalf("decision = %q, want %q (reason: %s)", result.Decision, tc.want, result.DecisionReason)
			}
			if tc.want == domain.DecisionEscalated && result.ActionTaken != domain.ActionEscalated {
				t.Errorf("action_taken = %q, want escalated", result.ActionTaken)
			}
		})
	}
}
