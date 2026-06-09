//go:build sqlite_strict

// Package sqlite provides a Classifier for SQLite SQL strings using
// github.com/rqlite/sql — a pure-Go SQLite SQL parser maintained as
// part of the rqlite distributed-SQLite project.
//
// Parser coverage is the rqlite-useful subset (everything DML/DDL/DCL
// plus PRAGMA, REINDEX, ANALYZE, CREATE TRIGGER). Statement shapes
// outside that subset (VACUUM, ATTACH DATABASE, DETACH, SAVEPOINT,
// RELEASE, EXPLAIN) currently return parse errors — the classifier
// surfaces them as parse errors and the engine fail-closes to deny.
// That's the correct outcome for those statements in an
// agentic-DB-access policy anyway.
package sqlite

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rqlite/sql"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const Dialect = "sqlite"

func init() {
	sqlguard.Register(&classifier{})
}

type classifier struct{}

func (classifier) Dialect() string { return Dialect }

func (c classifier) Classify(in string) (sqlguard.Classification, error) {
	// Pre-classifier: rqlite/sql doesn't grammar-parse some SQLite
	// statements that are nevertheless real (VACUUM, ATTACH DATABASE,
	// DETACH DATABASE, SAVEPOINT — though savepoint is now supported).
	// Detect their first keyword and surface them as explicit Kinds so
	// policies can route them, rather than letting them fall through
	// to a parse-error fail-closed.
	if cl, hit := preClassify(in); hit {
		return cl, nil
	}
	stmts, err := parseAll(in)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("sqlite parse: %w", err)
	}
	cl := sqlguard.Classification{Dialect: Dialect, StmtCount: len(stmts)}

	funcSet := map[string]struct{}{}
	for _, stmt := range stmts {
		kind := topLevelKind(stmt)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)
		switch kind {
		case sqlguard.KindCall, sqlguard.KindExecute, sqlguard.KindPrepare, sqlguard.KindDo:
			cl.UsesDynamicSQL = true
		}
		// Triggers carry an arbitrary statement body — treat as dynamic.
		if _, ok := stmt.(*sql.CreateTriggerStatement); ok {
			cl.UsesDynamicSQL = true
		}
		collectFunctions(stmt, funcSet)
	}
	if len(funcSet) > 0 {
		cl.Functions = make([]string, 0, len(funcSet))
		cl.FunctionsQualified = make([]string, 0, len(funcSet))
		for fn := range funcSet {
			cl.Functions = append(cl.Functions, fn)
			cl.FunctionsQualified = append(cl.FunctionsQualified, fn)
		}
		sort.Strings(cl.Functions)
		sort.Strings(cl.FunctionsQualified)
	}

	cl.ReadOnly = cl.IsPureSelect() && !cl.UsesDynamicSQL && !cl.UsesProgram
	return cl, nil
}

// parseAll uses rqlite/sql's Parser to consume every statement in the
// input separated by top-level semicolons.
func parseAll(text string) ([]sql.Statement, error) {
	p := sql.NewParser(strings.NewReader(text))
	var out []sql.Statement
	for {
		stmt, err := p.ParseStatement()
		if err != nil {
			if err.Error() == "EOF" || strings.Contains(err.Error(), "EOF") {
				return out, nil
			}
			return nil, err
		}
		if stmt == nil {
			break
		}
		out = append(out, stmt)
	}
	return out, nil
}

func topLevelKind(stmt sql.Statement) sqlguard.Kind {
	switch stmt.(type) {
	case *sql.SelectStatement:
		return sqlguard.KindSelect
	case *sql.InsertStatement:
		return sqlguard.KindInsert
	case *sql.UpdateStatement:
		return sqlguard.KindUpdate
	case *sql.DeleteStatement:
		return sqlguard.KindDelete
	case *sql.CreateTableStatement,
		*sql.CreateIndexStatement,
		*sql.CreateViewStatement,
		*sql.CreateTriggerStatement,
		*sql.CreateVirtualTableStatement:
		return sqlguard.KindCreate
	case *sql.DropTableStatement,
		*sql.DropIndexStatement,
		*sql.DropViewStatement,
		*sql.DropTriggerStatement:
		return sqlguard.KindDrop
	case *sql.AlterTableStatement:
		return sqlguard.KindAlter
	case *sql.BeginStatement,
		*sql.CommitStatement,
		*sql.RollbackStatement:
		return sqlguard.KindTransaction
	case *sql.PragmaStatement:
		// PRAGMA is the SQLite "set" — flag as KindSet for policy
		// purposes; operators almost always want to forbid PRAGMA
		// from an agent path.
		return sqlguard.KindSet
	case *sql.ReindexStatement, *sql.AnalyzeStatement:
		return sqlguard.KindOther
	}
	return sqlguard.KindOther
}

// collectFunctions walks the statement tree pulling out function-call
// names. rqlite/sql's AST has a Walk function we hook into via a
// minimal visitor.
func collectFunctions(stmt sql.Statement, out map[string]struct{}) {
	sql.Walk(walker{out: out}, stmt)
}

type walker struct {
	out map[string]struct{}
}

func (w walker) Visit(node sql.Node) (sql.Visitor, sql.Node, error) {
	if call, ok := node.(*sql.Call); ok {
		if call.Name != nil {
			name := strings.ToLower(call.Name.Name)
			if name != "" {
				w.out[name] = struct{}{}
			}
		}
	}
	return w, node, nil
}

func (w walker) VisitEnd(node sql.Node) (sql.Node, error) {
	return node, nil
}
