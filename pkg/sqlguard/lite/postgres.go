package lite

import (
	"fmt"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const dialectPostgres = "postgres"

var pgQuirks = DialectQuirks{
	DollarQuotes:           true,
	DoubleQuoteIdentifiers: true,
}

func init() {
	sqlguard.Register(&pgClassifier{})
}

type pgClassifier struct{}

func (pgClassifier) Dialect() string { return dialectPostgres }

func (p pgClassifier) Classify(in string) (sqlguard.Classification, error) {
	if strings.TrimSpace(in) == "" {
		return sqlguard.Classification{}, fmt.Errorf("postgres parse: empty input")
	}
	stripped, err := StripCommentsAndStrings(in, pgQuirks)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("postgres parse: %w", err)
	}
	parts := SplitTopLevelStatements(stripped)
	if len(parts) == 0 {
		return sqlguard.Classification{}, fmt.Errorf("postgres parse: no statements")
	}
	cl := sqlguard.Classification{Dialect: dialectPostgres, StmtCount: len(parts)}

	for _, part := range parts {
		first := FirstKeyword(part)
		// WITH ... AS (...) <DML> — the post-CTE keyword is the
		// REAL top-level statement. Pre-fix, "WITH x AS (SELECT 1)
		// DELETE FROM users" was classified as a SELECT because
		// the WITH-keyword wins. KeywordPastWith returns the first
		// non-trivia keyword after the balanced CTE definitions;
		// for plain SELECT-CTEs it returns SELECT.
		if first == "WITH" {
			if past := KeywordPastWith(part); past != "" {
				first = past
			}
		}
		kind := pgKeywordToKind(first)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		switch kind {
		case sqlguard.KindDo, sqlguard.KindExecute, sqlguard.KindPrepare, sqlguard.KindCall:
			cl.UsesDynamicSQL = true
		}

		// CREATE FUNCTION / PROCEDURE / TRIGGER bodies hold arbitrary SQL.
		if kind == sqlguard.KindCreate && ContainsAnyCI(part, []string{
			"create function", "create or replace function",
			"create procedure", "create or replace procedure",
			"create trigger",
		}) {
			cl.UsesDynamicSQL = true
		}

		// COPY ... FROM/TO PROGRAM is the shell-via-DB primitive.
		if kind == sqlguard.KindCopy && ContainsAnyCI(part, []string{
			"from program", "to program",
		}) {
			cl.UsesProgram = true
		}

		// Modifying CTE detection (same state machine as MSSQL).
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

func pgKeywordToKind(kw string) sqlguard.Kind {
	switch kw {
	case "SELECT", "WITH", "TABLE", "VALUES":
		return sqlguard.KindSelect
	case "INSERT":
		return sqlguard.KindInsert
	case "UPDATE":
		return sqlguard.KindUpdate
	case "DELETE":
		return sqlguard.KindDelete
	case "MERGE":
		return sqlguard.KindUpdate
	case "CREATE":
		return sqlguard.KindCreate
	case "DROP":
		return sqlguard.KindDrop
	case "TRUNCATE":
		return sqlguard.KindTruncate
	case "ALTER":
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
	case "PREPARE":
		return sqlguard.KindPrepare
	case "COPY":
		return sqlguard.KindCopy
	case "LOAD":
		return sqlguard.KindLoad
	case "SET":
		return sqlguard.KindSet
	case "DISCARD":
		return sqlguard.KindDiscard
	case "BEGIN", "COMMIT", "ROLLBACK", "START", "END", "ABORT", "SAVE", "RELEASE":
		return sqlguard.KindTransaction
	case "EXPLAIN":
		return sqlguard.KindOther
	case "VACUUM", "ANALYZE", "CLUSTER", "REINDEX", "LOCK", "CHECKPOINT", "REFRESH":
		return sqlguard.KindOther
	case "NOTIFY", "LISTEN", "UNLISTEN":
		return sqlguard.KindOther
	case "SHOW", "RESET":
		return sqlguard.KindOther
	}
	return sqlguard.KindOther
}
