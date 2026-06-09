//go:build mysql_strict

// Package mysql provides a Classifier for MySQL/MariaDB SQL strings
// using github.com/pingcap/tidb/pkg/parser — the same parser TiDB
// ships in production, MySQL-compatible grammar.
package mysql

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver" // value driver required by tidb parser

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const Dialect = "mysql"

// dangerousMySQLFunctions is a tiny reference list of file-touching /
// shell-touching MySQL functions a policy author probably wants to
// catch via AllowedFunctions. Exported only as a doc handle; policies
// declare their own allowlists.
var dangerousMySQLFunctions = []string{
	"load_file",      // reads file from disk into a scalar
	"sys_exec",       // user-defined function in older MariaDB plugins
	"sleep",          // simple DoS amplifier
	"benchmark",      // CPU burner
	"into_outfile",   // not technically a function — handled separately
	"into_dumpfile",  // same
}

func init() {
	sqlguard.Register(&classifier{})
}

type classifier struct{}

func (classifier) Dialect() string { return Dialect }

func (c classifier) Classify(sql string) (sqlguard.Classification, error) {
	p := parser.New()
	stmts, _, err := p.Parse(sql, "", "")
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("mysql parse: %w", err)
	}
	cl := sqlguard.Classification{Dialect: Dialect, StmtCount: len(stmts)}

	funcSet := map[string]struct{}{}
	for _, stmt := range stmts {
		kind := topLevelKind(stmt)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		// Dynamic-SQL flag: anything procedural / variable-based / EXECUTE-like.
		switch kind {
		case sqlguard.KindDo, sqlguard.KindCall, sqlguard.KindExecute, sqlguard.KindPrepare:
			cl.UsesDynamicSQL = true
		}
		// CREATE FUNCTION / PROCEDURE / TRIGGER bodies hold arbitrary SQL.
		if isMySQLCreateRoutine(stmt) {
			cl.UsesDynamicSQL = true
		}

		// LOAD DATA INFILE is the MySQL moral equivalent of COPY FROM PROGRAM:
		// it reads a server-side file path. We surface it as UsesProgram so
		// a policy that opts in to no_program_exec catches it without having
		// to enumerate per-dialect node types.
		if _, ok := stmt.(*ast.LoadDataStmt); ok {
			cl.UsesProgram = true
		}

		// Walk the AST collecting every function call.
		stmt.Accept(&funcVisitor{out: funcSet})
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

func topLevelKind(stmt ast.StmtNode) sqlguard.Kind {
	switch stmt.(type) {
	case *ast.SelectStmt:
		return sqlguard.KindSelect
	case *ast.InsertStmt:
		return sqlguard.KindInsert
	case *ast.UpdateStmt:
		return sqlguard.KindUpdate
	case *ast.DeleteStmt:
		return sqlguard.KindDelete
	case *ast.DropTableStmt,
		*ast.DropIndexStmt,
		*ast.DropDatabaseStmt,
		*ast.DropUserStmt,
		*ast.DropStatsStmt:
		return sqlguard.KindDrop
	case *ast.TruncateTableStmt:
		return sqlguard.KindTruncate
	case *ast.AlterTableStmt,
		*ast.AlterDatabaseStmt,
		*ast.AlterUserStmt:
		return sqlguard.KindAlter
	case *ast.CreateTableStmt,
		*ast.CreateIndexStmt,
		*ast.CreateDatabaseStmt,
		*ast.CreateUserStmt,
		*ast.CreateViewStmt,
		*ast.CreateSequenceStmt,
		*ast.CreateBindingStmt:
		return sqlguard.KindCreate
	case *ast.GrantStmt, *ast.GrantRoleStmt:
		return sqlguard.KindGrant
	case *ast.RevokeStmt, *ast.RevokeRoleStmt:
		return sqlguard.KindRevoke
	case *ast.SetStmt, *ast.SetPwdStmt:
		return sqlguard.KindSet
	case *ast.BeginStmt, *ast.CommitStmt, *ast.RollbackStmt:
		return sqlguard.KindTransaction
	case *ast.LoadDataStmt:
		// Treat MySQL's LOAD DATA INFILE as KindLoad — it loads
		// data from a server-side file. Different from Postgres LOAD
		// (shared library), but the operator intent in a policy
		// ("don't let agents load from the filesystem") covers both.
		return sqlguard.KindLoad
	case *ast.PrepareStmt:
		return sqlguard.KindPrepare
	case *ast.ExecuteStmt:
		return sqlguard.KindExecute
	case *ast.DeallocateStmt:
		return sqlguard.KindOther
	}
	// CallStmt and ProcedureInfo aren't always in the ast package's
	// public surface, so detect them by type name.
	name := fmt.Sprintf("%T", stmt)
	if strings.Contains(name, "CallStmt") {
		return sqlguard.KindCall
	}
	if strings.Contains(name, "ProcedureInfo") || strings.Contains(name, "ProcedureStmt") {
		return sqlguard.KindCreate
	}
	return sqlguard.KindOther
}

func isMySQLCreateRoutine(stmt ast.StmtNode) bool {
	name := fmt.Sprintf("%T", stmt)
	if strings.Contains(name, "ProcedureInfo") ||
		strings.Contains(name, "ProcedureStmt") ||
		strings.Contains(name, "CreateFunctionStmt") ||
		strings.Contains(name, "TriggerStmt") {
		return true
	}
	return false
}

// funcVisitor walks the AST collecting function names. Implements
// ast.Visitor.
type funcVisitor struct {
	out map[string]struct{}
}

func (v *funcVisitor) Enter(n ast.Node) (ast.Node, bool) {
	if fc, ok := n.(*ast.FuncCallExpr); ok {
		// FuncCallExpr.FnName is a model.CIStr — use its O (original).
		name := strings.ToLower(fc.FnName.L)
		if name == "" {
			name = strings.ToLower(fc.FnName.O)
		}
		if name != "" {
			v.out[name] = struct{}{}
		}
	}
	if agg, ok := n.(*ast.AggregateFuncExpr); ok {
		name := strings.ToLower(agg.F)
		if name != "" {
			v.out[name] = struct{}{}
		}
	}
	return n, false
}

func (v *funcVisitor) Leave(n ast.Node) (ast.Node, bool) {
	return n, true
}
