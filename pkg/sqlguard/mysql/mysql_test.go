//go:build mysql_strict

package mysql_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mysql"
)

func TestRegisteredViaInit(t *testing.T) {
	if _, ok := sqlguard.Get("mysql"); !ok {
		t.Fatalf("mysql classifier not registered")
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
		{"create table", "CREATE TABLE foo (id INT)", sqlguard.KindCreate},
		{"create view", "CREATE VIEW v AS SELECT * FROM users", sqlguard.KindCreate},
		{"drop table", "DROP TABLE users", sqlguard.KindDrop},
		{"truncate", "TRUNCATE TABLE users", sqlguard.KindTruncate},
		{"alter table", "ALTER TABLE users ADD COLUMN x INT", sqlguard.KindAlter},
		{"grant", "GRANT ALL ON users.* TO 'agent'@'%'", sqlguard.KindGrant},
		{"revoke", "REVOKE INSERT ON users.* FROM 'agent'@'%'", sqlguard.KindRevoke},
		{"call", "CALL my_proc()", sqlguard.KindCall},
		{"prepare", "PREPARE p FROM 'SELECT 1'", sqlguard.KindPrepare},
		{"execute", "EXECUTE p", sqlguard.KindExecute},
		{"set", "SET @x := 1", sqlguard.KindSet},
		{"begin", "BEGIN", sqlguard.KindTransaction},
		{"commit", "COMMIT", sqlguard.KindTransaction},
		{"load data infile", "LOAD DATA INFILE '/etc/passwd' INTO TABLE users", sqlguard.KindLoad},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := sqlguard.Classify("mysql", c.sql)
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

func TestMultiStatement(t *testing.T) {
	cl, err := sqlguard.Classify("mysql", "SELECT 1; DROP TABLE users")
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
		"SELECT u.id, p.amount FROM users u JOIN payments p ON p.user_id = u.id WHERE u.id < 100",
		"WITH q AS (SELECT 1) SELECT * FROM q",
	}
	mustNot := []string{
		"DROP TABLE users",
		"INSERT INTO users VALUES (1)",
		"CALL my_proc()",
		"LOAD DATA INFILE '/etc/passwd' INTO TABLE users",
		"SET @x := 1",
		"BEGIN",
		"GRANT ALL ON users.* TO 'agent'@'%'",
		"SELECT 1; DROP TABLE users",
	}
	for _, sql := range must {
		t.Run("pure/"+short(sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("mysql", sql)
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
			cl, err := sqlguard.Classify("mysql", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.IsPureSelect() {
				t.Fatalf("pure for %q: %+v", sql, cl)
			}
		})
	}
}

func TestUsesProgramAndDynamic(t *testing.T) {
	// LOAD DATA INFILE → UsesProgram = true (MySQL equivalent of COPY FROM PROGRAM)
	cl, _ := sqlguard.Classify("mysql", "LOAD DATA INFILE '/etc/passwd' INTO TABLE users")
	if !cl.UsesProgram {
		t.Errorf("UsesProgram=false for LOAD DATA INFILE")
	}
	// CALL → UsesDynamicSQL = true
	cl, _ = sqlguard.Classify("mysql", "CALL my_proc()")
	if !cl.UsesDynamicSQL {
		t.Errorf("UsesDynamicSQL=false for CALL")
	}
	// PREPARE → UsesDynamicSQL = true
	cl, _ = sqlguard.Classify("mysql", "PREPARE p FROM 'SELECT 1'")
	if !cl.UsesDynamicSQL {
		t.Errorf("UsesDynamicSQL=false for PREPARE")
	}
	// EXECUTE → UsesDynamicSQL = true
	cl, _ = sqlguard.Classify("mysql", "EXECUTE p")
	if !cl.UsesDynamicSQL {
		t.Errorf("UsesDynamicSQL=false for EXECUTE")
	}
}

func TestFunctionsCollected(t *testing.T) {
	cases := []struct {
		sql       string
		wantFuncs []string
	}{
		{"SELECT count(*) FROM users", []string{"count"}},
		{"SELECT load_file('/etc/passwd')", []string{"load_file"}},
		{"SELECT sleep(100)", []string{"sleep"}},
		{"SELECT benchmark(1000000, md5('hello'))", []string{"benchmark", "md5"}},
		{"SELECT count(*), sum(amount), max(created_at) FROM payments", []string{"count", "max", "sum"}},
	}
	for _, c := range cases {
		t.Run(short(c.sql), func(t *testing.T) {
			cl, err := sqlguard.Classify("mysql", c.sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := append([]string{}, cl.Functions...)
			sort.Strings(got)
			sort.Strings(c.wantFuncs)
			if !slicesEqual(got, c.wantFuncs) {
				t.Errorf("functions = %v, want %v", got, c.wantFuncs)
			}
		})
	}
}

func TestHasDisallowedFunction(t *testing.T) {
	allow := []string{"count", "sum", "avg", "min", "max", "now", "lower", "upper"}
	clean, _ := sqlguard.Classify("mysql", "SELECT count(*), sum(amount) FROM payments")
	if name, bad := clean.HasDisallowedFunction(allow); bad {
		t.Errorf("clean SELECT flagged disallowed %q", name)
	}
	dirty, _ := sqlguard.Classify("mysql", "SELECT load_file('/etc/passwd')")
	if name, bad := dirty.HasDisallowedFunction(allow); !bad || name != "load_file" {
		t.Errorf("did not flag load_file; got name=%q bad=%v", name, bad)
	}
	sleepy, _ := sqlguard.Classify("mysql", "SELECT sleep(100)")
	if name, bad := sleepy.HasDisallowedFunction(allow); !bad || name != "sleep" {
		t.Errorf("did not flag sleep; got name=%q bad=%v", name, bad)
	}
}

func TestParseError(t *testing.T) {
	_, err := sqlguard.Classify("mysql", "SELECT FROM WHERE")
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), "mysql parse") {
		t.Errorf("error doesn't wrap: %v", err)
	}
}

func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 50 {
		s = s[:47] + "..."
	}
	return s
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
