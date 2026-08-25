package engine_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"

	// Registers the lite (tokenizer) classifier for the postgres dialect.
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
)

func boolPtr(b bool) *bool { return &b }

type pathologicalSQLCase struct {
	name string
	sql  string
	// mustFire: nil = only require a bounded bool result and no panic;
	// non-nil also asserts the fire/no-fire verdict (true = deny).
	mustFire *bool
}

func pathologicalSQLCondition() domain.Condition {
	return domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{
				TopLevelKinds: []string{"SELECT"},
				NoDynamicSQL:  true,
				NoProgramExec: true,
			},
		},
	}
}

func pathologicalSQLCases() []pathologicalSQLCase {
	r := strings.Repeat
	return []pathologicalSQLCase{
		{"huge_select_columns", "SELECT " + r("a,", 200_000) + "a FROM t", nil},
		{"deep_nested_parens", "SELECT " + r("(", 20_000) + "1" + r(")", 20_000), nil},
		{"giant_in_list", "SELECT * FROM t WHERE id IN (" + r("1,", 100_000) + "1)", nil},
		{"comment_flood", "SELECT 1 " + r("/* noise */", 100_000), nil},
		{"string_literal_flood", "SELECT " + r("'aaaa',", 50_000) + "1", nil},
		{"whitespace_flood", "SELECT" + r(" ", 500_000) + "1", nil},
		{"null_bytes", "SELECT 1" + r("\x00", 2_000), nil},
		{"unterminated_string", "SELECT '" + r("a", 200_000), nil},
		// Malicious intent buried in noise — must still be denied.
		{"multi_stmt_drop_flood", r("SELECT 1;", 50_000) + "DROP TABLE t", boolPtr(true)},
		{"modifying_cte_buried", "WITH x AS (" + r("SELECT 1 UNION ", 5_000) +
			"SELECT 1), d AS (DELETE FROM t RETURNING *) SELECT * FROM d", boolPtr(true)},
	}
}

func evaluatePathologicalSQL(cond domain.Condition, sql string) (fired bool, panicked any) {
	defer func() { panicked = recover() }()
	fired = engine.EvalCondition(cond, sqlFields(sql))
	return fired, nil
}

func assertPathologicalSQLCorrectness(t *testing.T, tc pathologicalSQLCase, fired bool, panicked any) {
	t.Helper()
	if panicked != nil {
		t.Fatalf("EvalCondition panicked on %q (len=%d): %v", tc.name, len(tc.sql), panicked)
	}
	if tc.mustFire != nil && fired != *tc.mustFire {
		t.Errorf("%q: rule fired = %v, want %v — malicious SQL must fail closed despite the surrounding noise",
			tc.name, fired, *tc.mustFire)
	}
}

// TestStress_SQLClassifyPathologicalInput is the per-PR correctness gate for
// deliberately abusive SQL strings: hundred-thousand-token queries, deeply
// nested parentheses, comment/string floods, null bytes, and unterminated
// literals. It asserts the classifier returns without a panic and preserves
// fail-closed verdicts where intent is unambiguous.
//
// This test intentionally has no per-case wall-clock assertion. Shared CI
// runner speed must not make unrelated PRs fail. The Go test process and CI job
// timeouts still catch a true hang. The 2-second performance ceiling lives in
// sql_classify_performance_test.go and is invoked only by nightly-stress.yml.
func TestStress_SQLClassifyPathologicalInput(t *testing.T) {
	cond := pathologicalSQLCondition()
	for _, tc := range pathologicalSQLCases() {
		t.Run(tc.name, func(t *testing.T) {
			fired, panicked := evaluatePathologicalSQL(cond, tc.sql)
			assertPathologicalSQLCorrectness(t, tc, fired, panicked)
		})
	}
}
