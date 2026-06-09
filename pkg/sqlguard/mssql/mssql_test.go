package mssql_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mssql"
)

func TestRegisteredViaInit(t *testing.T) {
	if _, ok := sqlguard.Get("mssql"); !ok {
		t.Fatalf("mssql classifier not registered")
	}
}

func TestTopLevelKind(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want sqlguard.Kind
	}{
		{"plain select", "SELECT 1", sqlguard.KindSelect},
		{"select with cte", "WITH q AS (SELECT 1) SELECT * FROM q", sqlguard.KindSelect},
		{"insert", "INSERT INTO users (id) VALUES (1)", sqlguard.KindInsert},
		{"update", "UPDATE users SET email='x'", sqlguard.KindUpdate},
		{"delete", "DELETE FROM users", sqlguard.KindDelete},
		{"merge (write)", "MERGE users AS t USING src AS s ON t.id=s.id WHEN MATCHED THEN UPDATE SET email='x';", sqlguard.KindUpdate},
		{"create table", "CREATE TABLE foo (id INT)", sqlguard.KindCreate},
		{"create procedure", "CREATE PROCEDURE p AS BEGIN SELECT 1 END", sqlguard.KindCreate},
		{"drop table", "DROP TABLE users", sqlguard.KindDrop},
		{"truncate", "TRUNCATE TABLE users", sqlguard.KindTruncate},
		{"alter table", "ALTER TABLE users ADD x INT", sqlguard.KindAlter},
		{"grant", "GRANT SELECT ON users TO agent", sqlguard.KindGrant},
		{"revoke", "REVOKE SELECT ON users FROM agent", sqlguard.KindRevoke},
		{"deny", "DENY SELECT ON users TO agent", sqlguard.KindRevoke},
		{"exec", "EXEC sp_who", sqlguard.KindExecute},
		{"execute", "EXECUTE sp_who", sqlguard.KindExecute},
		{"begin tran", "BEGIN TRANSACTION", sqlguard.KindTransaction},
		{"commit", "COMMIT", sqlguard.KindTransaction},
		{"rollback", "ROLLBACK", sqlguard.KindTransaction},
		{"set", "SET @x = 1", sqlguard.KindSet},
		{"declare", "DECLARE @x INT", sqlguard.KindSet},
		{"use db", "USE master", sqlguard.KindSet},
		{"bulk insert (load)", "BULK INSERT users FROM 'C:\\path\\file.csv'", sqlguard.KindOther},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, err := sqlguard.Classify("mssql", c.sql)
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
	cl, _ := sqlguard.Classify("mssql", "SELECT 1; DROP TABLE users")
	if cl.StmtCount != 2 {
		t.Fatalf("stmt_count=%d, want 2", cl.StmtCount)
	}
	if cl.IsPureSelect() {
		t.Fatalf("multi-stmt should not be pure")
	}
}

func TestGoBatchSeparator(t *testing.T) {
	// T-SQL: GO is a batch separator, not a statement
	sqlStr := "SELECT 1\nGO\nDROP TABLE users\nGO"
	cl, err := sqlguard.Classify("mssql", sqlStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cl.StmtCount != 2 {
		t.Fatalf("expected 2 statements (split by GO), got %d", cl.StmtCount)
	}
}

func TestStringLiteralsHideSemicolons(t *testing.T) {
	// The ; inside the string must NOT count as a statement separator.
	cl, err := sqlguard.Classify("mssql", "SELECT 'x;y;z' AS s")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cl.StmtCount != 1 {
		t.Fatalf("string-literal ; was counted as separator: got %d stmts", cl.StmtCount)
	}
}

func TestCommentsAreStripped(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql", "-- inline DROP TABLE\nSELECT 1")
	if !cl.IsPureSelect() {
		t.Errorf("inline comment leaked into classification")
	}
	cl, _ = sqlguard.Classify("mssql", "/* block DROP TABLE */ SELECT 1")
	if !cl.IsPureSelect() {
		t.Errorf("block comment leaked into classification")
	}
}

func TestUsesProgram_XpCmdshell(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql", "EXEC xp_cmdshell 'whoami'")
	if !cl.UsesProgram {
		t.Errorf("UsesProgram=false for xp_cmdshell")
	}
}

func TestUsesProgram_Openrowset(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql",
		"SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\system.ini', SINGLE_CLOB) AS x")
	if !cl.UsesProgram {
		t.Errorf("UsesProgram=false for OPENROWSET")
	}
}

func TestUsesDynamicSQL_SpExecutesql(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql", "EXEC sp_executesql N'DROP TABLE users'")
	if !cl.UsesDynamicSQL {
		t.Errorf("UsesDynamicSQL=false for sp_executesql")
	}
}

func TestUsesDynamicSQL_CreateProcedure(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql", "CREATE PROCEDURE p AS BEGIN SELECT 1 END")
	if !cl.UsesDynamicSQL {
		t.Errorf("UsesDynamicSQL=false for CREATE PROCEDURE")
	}
}

func TestIsPureSelect(t *testing.T) {
	mustPure := []string{
		"SELECT 1",
		"SELECT id FROM users",
		"WITH q AS (SELECT 1) SELECT * FROM q",
	}
	mustDirty := []string{
		"DROP TABLE users",
		"INSERT INTO users VALUES (1)",
		"EXEC xp_cmdshell 'whoami'",
		"EXEC sp_executesql N'DROP TABLE users'",
		"BULK INSERT users FROM 'C:\\file.csv'",
		"SELECT 1; DROP TABLE users",
		"CREATE PROCEDURE p AS BEGIN SELECT 1 END",
		"BEGIN TRANSACTION",
		"SET @x = 1",
	}
	for _, s := range mustPure {
		t.Run("pure/"+short(s), func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", s)
			if !cl.IsPureSelect() {
				t.Errorf("not pure for %q: %+v", s, cl)
			}
		})
	}
	for _, s := range mustDirty {
		t.Run("dirty/"+short(s), func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", s)
			if cl.IsPureSelect() {
				t.Errorf("pure for %q: %+v", s, cl)
			}
		})
	}
}

// OPENROWSET top-level shape is a SELECT, so IsPureSelect() is true
// (a syntactic property). What protects us is the UsesProgram flag,
// which the policy's NoProgramExec require uses to deny the call.
func TestOpenrowsetIsSelectButUsesProgram(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql",
		"SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\system.ini', SINGLE_CLOB) AS x")
	if !cl.IsPureSelect() {
		t.Errorf("OPENROWSET top-level IS a SELECT; IsPureSelect should be true")
	}
	if !cl.UsesProgram {
		t.Errorf("OPENROWSET must flag UsesProgram=true so NoProgramExec catches it")
	}
}

func TestFunctionsCollected(t *testing.T) {
	cl, _ := sqlguard.Classify("mssql", "SELECT COUNT(*), MAX(created_at) FROM users")
	want := []string{"count", "max"}
	for _, w := range want {
		found := false
		for _, got := range cl.Functions {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %q in %v", w, cl.Functions)
		}
	}
}

func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 50 {
		s = s[:47] + "..."
	}
	return s
}
