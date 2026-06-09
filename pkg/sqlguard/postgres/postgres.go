//go:build pg_strict

// Package postgres provides a Classifier for PostgreSQL SQL strings
// by wrapping pganalyze/pg_query_go (cgo binding to libpg_query, the
// real Postgres grammar carved out of the server source).
package postgres

import (
	"fmt"
	"sort"

	pg_query "github.com/pganalyze/pg_query_go/v5"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const Dialect = "postgres"

func init() {
	sqlguard.Register(&classifier{})
}

type classifier struct{}

func (classifier) Dialect() string { return Dialect }

func (c classifier) Classify(sql string) (sqlguard.Classification, error) {
	res, err := pg_query.Parse(sql)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("postgres parse: %w", err)
	}
	cl := sqlguard.Classification{Dialect: Dialect, StmtCount: len(res.Stmts)}

	funcSet := map[string]struct{}{}
	qualSet := map[string]struct{}{}
	addFunc := func(qualified, last string) {
		if last != "" {
			funcSet[last] = struct{}{}
		}
		if qualified != "" {
			qualSet[qualified] = struct{}{}
		}
	}

	for _, raw := range res.Stmts {
		if raw == nil || raw.Stmt == nil {
			continue
		}
		kind := topLevelKind(raw.Stmt)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		// Dynamic-SQL flag — set by ANY top-level form that constructs
		// or runs SQL at runtime. Anonymous DO blocks, EXECUTE, PREPARE,
		// CREATE FUNCTION with a body, plus the procedural CALL form.
		switch kind {
		case sqlguard.KindDo, sqlguard.KindExecute, sqlguard.KindPrepare, sqlguard.KindCall:
			cl.UsesDynamicSQL = true
		}
		if kind == sqlguard.KindCreate {
			// CREATE FUNCTION / PROCEDURE introduces a body that can run
			// arbitrary SQL at later invocation time. Treat as dynamic.
			if isCreateRoutine(raw.Stmt) {
				cl.UsesDynamicSQL = true
			}
		}

		// Postgres' COPY ... FROM/TO PROGRAM is the moral equivalent of
		// shell access via the database engine.
		if kind == sqlguard.KindCopy {
			if isCopyProgram(raw.Stmt) {
				cl.UsesProgram = true
			}
		}

		// Walk the whole statement tree to collect every FuncCall node
		// so the policy can run a function-allowlist check. The walker
		// is intentionally generic: it picks up FuncCall in any
		// expression context (SELECT projection, WHERE clause,
		// argument to another function, ORDER BY, etc.).
		//
		// During the same walk, detect modifying CTEs:
		// InsertStmt/UpdateStmt/DeleteStmt/MergeStmt nodes nested
		// inside a SELECT (or any "read" top-level) flag
		// MutatesViaCTE — that's the Postgres data-modifying-CTE
		// trick where the top-level looks like a benign SELECT but
		// the CTE actually writes during execution.
		isReadTop := kind == sqlguard.KindSelect
		var seenMutating bool
		walk(raw.Stmt, func(n *pg_query.Node) {
			if fc := n.GetFuncCall(); fc != nil {
				qualified, last := funcName(fc)
				addFunc(qualified, last)
			}
			// Skip the root node itself when checking for nested
			// mutations — the root's kind already covers the
			// top-level case.
			if n == raw.Stmt {
				return
			}
			if isReadTop {
				switch n.Node.(type) {
				case *pg_query.Node_InsertStmt,
					*pg_query.Node_UpdateStmt,
					*pg_query.Node_DeleteStmt,
					*pg_query.Node_MergeStmt:
					seenMutating = true
				}
			}
		})
		if seenMutating {
			cl.MutatesViaCTE = true
		}
	}

	cl.Functions = sortedKeys(funcSet)
	cl.FunctionsQualified = sortedKeys(qualSet)

	// ReadOnly is derived for PG (the native parser doesn't expose it).
	cl.ReadOnly = derivedReadOnly(&cl)

	return cl, nil
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// derivedReadOnly: a Postgres statement is treated as read-only when it
// is a single SELECT and is not flagged as dynamic-SQL or program-exec.
func derivedReadOnly(c *sqlguard.Classification) bool {
	if !c.IsPureSelect() {
		return false
	}
	if c.UsesDynamicSQL || c.UsesProgram {
		return false
	}
	return true
}

func topLevelKind(node *pg_query.Node) sqlguard.Kind {
	if node == nil || node.Node == nil {
		return sqlguard.KindUnknown
	}
	switch node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return sqlguard.KindSelect
	case *pg_query.Node_InsertStmt:
		return sqlguard.KindInsert
	case *pg_query.Node_UpdateStmt:
		return sqlguard.KindUpdate
	case *pg_query.Node_DeleteStmt:
		return sqlguard.KindDelete
	case *pg_query.Node_CreateStmt,
		*pg_query.Node_CreateFunctionStmt,
		*pg_query.Node_CreateRoleStmt,
		*pg_query.Node_CreateSchemaStmt,
		*pg_query.Node_CreateExtensionStmt,
		*pg_query.Node_CreateTrigStmt,
		*pg_query.Node_ViewStmt,
		*pg_query.Node_IndexStmt:
		return sqlguard.KindCreate
	case *pg_query.Node_DropStmt:
		return sqlguard.KindDrop
	case *pg_query.Node_TruncateStmt:
		return sqlguard.KindTruncate
	case *pg_query.Node_AlterTableStmt,
		*pg_query.Node_AlterRoleStmt,
		*pg_query.Node_AlterFunctionStmt:
		return sqlguard.KindAlter
	case *pg_query.Node_GrantStmt:
		return sqlguard.KindGrant
	case *pg_query.Node_GrantRoleStmt:
		return sqlguard.KindGrant
	case *pg_query.Node_DoStmt:
		return sqlguard.KindDo
	case *pg_query.Node_CallStmt:
		return sqlguard.KindCall
	case *pg_query.Node_ExecuteStmt:
		return sqlguard.KindExecute
	case *pg_query.Node_PrepareStmt:
		return sqlguard.KindPrepare
	case *pg_query.Node_CopyStmt:
		return sqlguard.KindCopy
	case *pg_query.Node_LoadStmt:
		return sqlguard.KindLoad
	case *pg_query.Node_VariableSetStmt:
		return sqlguard.KindSet
	case *pg_query.Node_DiscardStmt:
		return sqlguard.KindDiscard
	case *pg_query.Node_TransactionStmt:
		return sqlguard.KindTransaction
	}
	return sqlguard.KindOther
}

func isCreateRoutine(node *pg_query.Node) bool {
	if node == nil {
		return false
	}
	if _, ok := node.Node.(*pg_query.Node_CreateFunctionStmt); ok {
		return true
	}
	return false
}

func isCopyProgram(node *pg_query.Node) bool {
	if node == nil {
		return false
	}
	if cs, ok := node.Node.(*pg_query.Node_CopyStmt); ok && cs.CopyStmt != nil {
		return cs.CopyStmt.IsProgram
	}
	return false
}

// funcName extracts the qualified and unqualified name from a FuncCall
// node. Postgres function names are a list of String nodes; we join
// them with dots for the qualified form and take the last element as
// the unqualified name.
func funcName(fc *pg_query.FuncCall) (qualified, last string) {
	if fc == nil {
		return "", ""
	}
	parts := make([]string, 0, len(fc.Funcname))
	for _, n := range fc.Funcname {
		if n == nil {
			continue
		}
		if s := n.GetString_(); s != nil && s.Sval != "" {
			parts = append(parts, s.Sval)
		}
	}
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], parts[0]
	}
	qualified = parts[0]
	for i := 1; i < len(parts); i++ {
		qualified += "." + parts[i]
	}
	return qualified, parts[len(parts)-1]
}
