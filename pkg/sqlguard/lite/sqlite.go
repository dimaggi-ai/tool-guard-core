package lite

import (
	"fmt"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const dialectSQLite = "sqlite"

var sqliteQuirks = DialectQuirks{
	DoubleQuoteIdentifiers: true,
	BracketIdentifiers:     true,
}

func init() {
	sqlguard.Register(&sqliteClassifier{})
}

type sqliteClassifier struct{}

func (sqliteClassifier) Dialect() string { return dialectSQLite }

func (c sqliteClassifier) Classify(in string) (sqlguard.Classification, error) {
	if strings.TrimSpace(in) == "" {
		return sqlguard.Classification{}, fmt.Errorf("sqlite parse: empty input")
	}
	stripped, err := StripCommentsAndStrings(in, sqliteQuirks)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("sqlite parse: %w", err)
	}
	parts := SplitTopLevelStatements(stripped)
	if len(parts) == 0 {
		return sqlguard.Classification{}, fmt.Errorf("sqlite parse: no statements")
	}
	cl := sqlguard.Classification{Dialect: dialectSQLite, StmtCount: len(parts)}

	for _, part := range parts {
		first := FirstKeyword(part)
		kind := sqliteKeywordToKind(first)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		// ATTACH DATABASE 'path' is the SQLite file-read primitive.
		if first == "ATTACH" {
			cl.UsesProgram = true
		}

		// Triggers carry a body of arbitrary SQL.
		if first == "CREATE" && ContainsAnyCI(part, []string{"create trigger"}) {
			cl.UsesDynamicSQL = true
		}

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

func sqliteKeywordToKind(kw string) sqlguard.Kind {
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
	case "ALTER":
		return sqlguard.KindAlter
	case "PRAGMA":
		return sqlguard.KindSet
	case "ATTACH", "DETACH":
		return sqlguard.KindOther
	case "BEGIN", "COMMIT", "ROLLBACK", "END", "SAVEPOINT", "RELEASE":
		return sqlguard.KindTransaction
	case "VACUUM", "ANALYZE", "REINDEX":
		return sqlguard.KindOther
	case "EXPLAIN":
		return sqlguard.KindOther
	}
	return sqlguard.KindOther
}
