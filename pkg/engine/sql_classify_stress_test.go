package engine_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"

	// Registers the lite (tokenizer) classifier for the postgres dialect.
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
)

func boolPtr(b bool) *bool { return &b }

// TestStress_SQLClassifyPathologicalInput feeds the SQL classifier deliberately
// abusive strings — hundred-thousand-token queries, tens of thousands of nested
// parentheses, comment/string floods, null bytes, unterminated literals — and
// asserts every one is classified within a hard time bound and never panics.
// The classifier runs inline on every tool call, so unbounded recursion or
// catastrophic backtracking here would be a denial-of-service vector. Where the
// intent is unambiguous (a buried modifying CTE, a multi-statement DROP) the
// rule must still fire (fail-closed to deny) despite the surrounding noise.
func TestStress_SQLClassifyPathologicalInput(t *testing.T) {
	cond := domain.Condition{
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

	r := strings.Repeat
	cases := []struct {
		name string
		sql  string
		// mustFire: nil = only require "returns fast, no panic"; non-nil =
		// also assert the fire/no-fire verdict (true = deny).
		mustFire *bool
	}{
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

	const budget = 2 * time.Second
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			done := make(chan struct{})
			var fired bool
			var panicked any
			go func() {
				defer func() {
					panicked = recover()
					close(done)
				}()
				fired = engine.EvalCondition(cond, sqlFields(tc.sql))
			}()

			select {
			case <-done:
			case <-time.After(budget):
				t.Fatalf("EvalCondition did not return within %s on %q (len=%d) — possible unbounded recursion or catastrophic backtracking",
					budget, tc.name, len(tc.sql))
			}
			if panicked != nil {
				t.Fatalf("EvalCondition panicked on %q (len=%d): %v", tc.name, len(tc.sql), panicked)
			}
			if tc.mustFire != nil && fired != *tc.mustFire {
				t.Errorf("%q: rule fired = %v, want %v — malicious SQL must fail closed despite the surrounding noise",
					tc.name, fired, *tc.mustFire)
			}
		})
	}
}
