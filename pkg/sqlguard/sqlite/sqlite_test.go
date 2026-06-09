//go:build sqlite_strict

package sqlite_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/sqlite"
)

func TestRegisteredViaInit(t *testing.T) {
	if _, ok := sqlguard.Get("sqlite"); !ok {
		t.Fatalf("sqlite classifier not registered")
	}
}

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
		{"create table", "CREATE TABLE foo (id INTEGER)", sqlguard.KindCreate},
		{"create view", "CREATE VIEW v AS SELECT * FROM users", sqlguard.KindCreate},
		{"create trigger", "CREATE TRIGGER t AFTER INSERT ON users BEGIN UPDATE users SET email='x'; END", sqlguard.KindCreate},
		{"drop table", "DROP TABLE users", sqlguard.KindDrop},
		{"alter table", "ALTER TABLE users ADD COLUMN x INTEGER", sqlguard.KindAlter},
		{"begin", "BEGIN", sqlguard.KindTransaction},
		{"commit", "COMMIT", sqlguard.KindTransaction},
		{"rollback", "ROLLBACK", sqlguard.KindTransaction},
		{"pragma", "PRAGMA journal_mode = WAL", sqlguard.KindSet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := sqlguard.Classify("sqlite", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.StmtCount != 1 {
				t.Fatalf("stmt_count=%d, want 1", cl.StmtCount)
			}
			if cl.TopLevelKinds[0] != c.want {
				t.Fatalf("top_level=%v, want [%s]", cl.TopLevelKinds, c.want)
			}
		})
	}
}

func TestMultiStatement(t *testing.T) {
	cl, err := sqlguard.Classify("sqlite", "SELECT 1; DROP TABLE users")
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

func TestIsPureSelect(t *testing.T) {
	must := []string{
		"SELECT 1",
		"SELECT id, email FROM users",
		"SELECT count(*) FROM payments",
		"WITH q AS (SELECT 1) SELECT * FROM q",
	}
	mustNot := []string{
		"DROP TABLE users",
		"INSERT INTO users VALUES (1)",
		"BEGIN",
		"PRAGMA journal_mode = WAL",
		"CREATE TRIGGER t AFTER INSERT ON users BEGIN UPDATE users SET email='x'; END",
		"SELECT 1; DROP TABLE users",
	}
	for _, sql := range must {
		t.Run("pure/"+short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("sqlite", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !cl.IsPureSelect() {
				t.Fatalf("not pure for %q: %+v", sql, cl)
			}
		})
	}
	for _, sql := range mustNot {
		t.Run("dirty/"+short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("sqlite", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.IsPureSelect() {
				t.Fatalf("pure for %q: %+v", sql, cl)
			}
		})
	}
}

// SQLite statement shapes that rqlite/sql does NOT grammar-parse are
// caught by the pre-classifier and surfaced with explicit Kinds so
// policies can route them rather than fail-closed.
func TestPreClassifierHandlesUnsupportedStatements(t *testing.T) {
	cases := map[string]struct {
		kind        sqlguard.Kind
		usesProgram bool
	}{
		"VACUUM":                                   {sqlguard.KindOther, false},
		"ATTACH DATABASE '/etc/passwd' AS attacker": {sqlguard.KindOther, true},
		"DETACH DATABASE attacker":                  {sqlguard.KindOther, false},
		"SAVEPOINT my_save":                         {sqlguard.KindTransaction, false},
		"RELEASE my_save":                           {sqlguard.KindTransaction, false},
	}
	for sql, want := range cases {
		t.Run(short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("sqlite", sql)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if len(cl.TopLevelKinds) != 1 || cl.TopLevelKinds[0] != want.kind {
				t.Errorf("kind=%v, want [%s]", cl.TopLevelKinds, want.kind)
			}
			if cl.UsesProgram != want.usesProgram {
				t.Errorf("uses_program=%v, want %v", cl.UsesProgram, want.usesProgram)
			}
		})
	}
}

func TestFunctionsCollected(t *testing.T) {
	cases := []struct {
		sql       string
		wantFuncs []string
	}{
		{"SELECT count(*) FROM users", []string{"count"}},
		{"SELECT count(*), sum(amount), max(created_at) FROM payments", []string{"count", "max", "sum"}},
		{"SELECT json_extract(data, '$.email') FROM users", []string{"json_extract"}},
	}
	for _, c := range cases {
		t.Run(short(c.sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("sqlite", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, want := range c.wantFuncs {
				found := false
				for _, got := range cl.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing %q in %v", want, cl.Functions)
				}
			}
		})
	}
}

func short(s string) string {
	if len(s) > 50 {
		s = s[:47] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}
