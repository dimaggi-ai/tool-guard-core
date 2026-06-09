package lite

import (
	"fmt"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const dialectMySQL = "mysql"

var mysqlQuirks = DialectQuirks{
	BacktickIdentifiers:    true,
	DoubleQuoteIdentifiers: true,
}

func init() {
	sqlguard.Register(&mysqlClassifier{})
}

type mysqlClassifier struct{}

func (mysqlClassifier) Dialect() string { return dialectMySQL }

func (m mysqlClassifier) Classify(in string) (sqlguard.Classification, error) {
	if strings.TrimSpace(in) == "" {
		return sqlguard.Classification{}, fmt.Errorf("mysql parse: empty input")
	}
	stripped, err := StripCommentsAndStrings(in, mysqlQuirks)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("mysql parse: %w", err)
	}
	parts := SplitTopLevelStatements(stripped)
	if len(parts) == 0 {
		return sqlguard.Classification{}, fmt.Errorf("mysql parse: no statements")
	}
	cl := sqlguard.Classification{Dialect: dialectMySQL, StmtCount: len(parts)}

	for _, part := range parts {
		first := FirstKeyword(part)
		kind := mysqlKeywordToKind(first)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		switch kind {
		case sqlguard.KindCall, sqlguard.KindExecute, sqlguard.KindPrepare, sqlguard.KindDo:
			cl.UsesDynamicSQL = true
		}

		// CREATE FUNCTION / PROCEDURE / TRIGGER bodies hold arbitrary SQL.
		if kind == sqlguard.KindCreate && ContainsAnyCI(part, []string{
			"create function", "create procedure", "create trigger", "create event",
		}) {
			cl.UsesDynamicSQL = true
		}

		// LOAD DATA INFILE is MySQL's moral equivalent of COPY FROM PROGRAM.
		if kind == sqlguard.KindLoad || ContainsAnyCI(part, []string{
			"load data infile", "load data local infile", "load_file",
		}) {
			cl.UsesProgram = true
		}

		// SELECT ... INTO OUTFILE writes server-side files.
		if kind == sqlguard.KindSelect && ContainsAnyCI(part, []string{
			"into outfile", "into dumpfile",
		}) {
			cl.UsesProgram = true
		}

		// Modifying CTE: MySQL 8 supports WITH ... AS (UPDATE ...)
		// although it's more limited than PG. Same state machine.
		if kind == sqlguard.KindSelect && HasModifyingCTE(part) {
			cl.MutatesViaCTE = true
		}
	}

	for _, fn := range CollectFunctions(stripped) {
		cl.Functions = append(cl.Functions, fn)
		cl.FunctionsQualified = append(cl.FunctionsQualified, fn)
	}
	cl.Tables = CollectTables(stripped)

	cl.ReadOnly = cl.IsPureSelect() && !cl.UsesDynamicSQL && !cl.UsesProgram && !cl.MutatesViaCTE
	return cl, nil
}

func mysqlKeywordToKind(kw string) sqlguard.Kind {
	switch kw {
	case "SELECT", "WITH", "TABLE", "VALUES":
		return sqlguard.KindSelect
	case "INSERT", "REPLACE":
		return sqlguard.KindInsert
	case "UPDATE":
		return sqlguard.KindUpdate
	case "DELETE":
		return sqlguard.KindDelete
	case "CREATE":
		return sqlguard.KindCreate
	case "DROP":
		return sqlguard.KindDrop
	case "TRUNCATE":
		return sqlguard.KindTruncate
	case "ALTER", "RENAME":
		return sqlguard.KindAlter
	case "GRANT":
		return sqlguard.KindGrant
	case "REVOKE":
		return sqlguard.KindRevoke
	case "DO":
		return sqlguard.KindDo
	case "CALL":
		return sqlguard.KindCall
	case "EXECUTE":
		return sqlguard.KindExecute
	case "PREPARE", "DEALLOCATE":
		return sqlguard.KindPrepare
	case "LOAD":
		return sqlguard.KindLoad
	case "SET", "DECLARE":
		return sqlguard.KindSet
	case "BEGIN", "COMMIT", "ROLLBACK", "START", "SAVEPOINT", "RELEASE":
		return sqlguard.KindTransaction
	case "EXPLAIN", "DESCRIBE", "DESC":
		return sqlguard.KindOther
	case "ANALYZE", "OPTIMIZE", "REPAIR", "CHECK", "FLUSH", "RESET":
		return sqlguard.KindOther
	case "SHOW", "USE":
		return sqlguard.KindOther
	case "LOCK", "UNLOCK":
		return sqlguard.KindOther
	}
	return sqlguard.KindOther
}
