package mssql_test

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mssql"
)

// MS T-SQL modifying CTE — same bypass class as Postgres, different
// keyword (OUTPUT instead of RETURNING).
func TestMSSQL_Breakage_ModifyingCTEs(t *testing.T) {
	cases := []string{
		"WITH d AS (DELETE FROM users OUTPUT deleted.id) SELECT * FROM d",
		"WITH u AS (UPDATE users SET email='x' OUTPUT inserted.id) SELECT * FROM u",
		"WITH i AS (INSERT INTO users VALUES (1,'evil') OUTPUT inserted.id) SELECT * FROM i",
		"WITH m AS (MERGE INTO users USING src ON users.id=src.id WHEN MATCHED THEN UPDATE SET email='x' OUTPUT inserted.id) SELECT * FROM m",
		// Without OUTPUT — still a modifying CTE
		"WITH d AS (DELETE FROM users) SELECT 1",
	}
	for _, sql := range cases {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			cl, err := sqlguard.Classify("mssql", sql)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cl.IsPureSelect() && !cl.MutatesViaCTE {
				t.Errorf("BYPASS: modifying CTE %q classified as pure SELECT without MutatesViaCTE flag; %+v", sql, cl)
			}
		})
	}
}

// Clean CTE without mutation must NOT flag.
func TestMSSQL_Breakage_CleanCTEsPassThrough(t *testing.T) {
	cases := []string{
		"WITH q AS (SELECT id FROM users) SELECT * FROM q",
		"WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a, b",
		"WITH r AS (SELECT id FROM users WHERE id < 10) SELECT count(*) FROM r",
	}
	for _, sql := range cases {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", sql)
			if cl.MutatesViaCTE {
				t.Errorf("OVERBLOCK: clean SELECT %q flagged as MutatesViaCTE", sql)
			}
		})
	}
}

// sp_configure + RECONFIGURE — the prelude to xp_cmdshell enabling.
func TestMSSQL_Breakage_ReconfigureSequence(t *testing.T) {
	cases := []string{
		"EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
		"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
		"RECONFIGURE WITH OVERRIDE",
	}
	for _, sql := range cases {
		t.Run(sql[:min(40, len(sql))], func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", sql)
			if !cl.UsesDynamicSQL {
				t.Errorf("RECONFIGURE/sp_configure not flagged as dynamic: %+v", cl)
			}
		})
	}
}

// WAITFOR DELAY / TIME — time-based DoS / blind injection.
func TestMSSQL_Breakage_WaitforTimeBased(t *testing.T) {
	cases := []string{
		"WAITFOR DELAY '00:00:30'",
		"WAITFOR TIME '23:59:59'",
		"IF (SELECT count(*) FROM users) > 0 WAITFOR DELAY '00:00:10'",
	}
	for _, sql := range cases {
		t.Run(sql[:min(40, len(sql))], func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", sql)
			if !cl.UsesDynamicSQL {
				t.Errorf("WAITFOR not flagged: %+v", cl)
			}
		})
	}
}

// File / remote-data primitives beyond OPENROWSET — full list.
func TestMSSQL_Breakage_FileAndRemotePrimitives(t *testing.T) {
	cases := []string{
		"SELECT * FROM OPENROWSET(BULK 'C:\\file', SINGLE_CLOB) AS x",
		"SELECT * FROM OPENDATASOURCE('SQLNCLI','...').db.dbo.tbl",
		"SELECT * FROM OPENQUERY(linked, 'SELECT 1')",
		"SELECT * FROM OPENXML(@idoc, '/root', 1)",
		"SELECT * FROM OPENJSON(@data, '$.items')",
		"EXEC sp_xml_preparedocument @idoc OUTPUT, @xml",
		"BULK INSERT users FROM 'C:\\file.csv'",
	}
	for _, sql := range cases {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", sql)
			if !cl.UsesProgram {
				t.Errorf("file/remote primitive not flagged: %+v", cl)
			}
		})
	}
}

// Linked-server 4-part names.
func TestMSSQL_Breakage_LinkedServerFourPartName(t *testing.T) {
	cases := []string{
		"SELECT * FROM linkedserver.dbname.dbo.tablename",
		"SELECT * FROM [LINKED].[master].[dbo].[sysrolemembers]",
		"INSERT INTO remote.db.dbo.tbl SELECT * FROM local",
	}
	for _, sql := range cases {
		t.Run(sql[:min(50, len(sql))], func(t *testing.T) {
			cl, _ := sqlguard.Classify("mssql", sql)
			if !cl.UsesProgram {
				t.Errorf("4-part name not flagged: %+v", cl)
			}
		})
	}
}

// Cursor declarations.
func TestMSSQL_Breakage_CursorDeclare(t *testing.T) {
	sql := "DECLARE c CURSOR FOR SELECT id FROM users"
	cl, _ := sqlguard.Classify("mssql", sql)
	if !cl.UsesDynamicSQL {
		t.Errorf("DECLARE CURSOR not flagged: %+v", cl)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
