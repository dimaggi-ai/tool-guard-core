// Package mssql provides a heuristic Classifier for Microsoft
// SQL Server / Azure SQL T-SQL strings.
//
// Caveat: there is no mature Go-native T-SQL parser. This classifier
// is a small hand-rolled tokenizer that:
//
//  1. strips T-SQL comments (-- and /* */)
//  2. strips string literals ('...' and [...]) so semicolons inside
//     them don't fool the splitter
//  3. splits on top-level ; into statements
//  4. identifies each statement's top-level Kind by the first
//     identifier-shaped token
//  5. flags the family of MSSQL dynamic-SQL / shell / file primitives
//     by name (xp_cmdshell, sp_executesql, OPENROWSET, BULK INSERT)
//  6. heuristically collects function-call names via `\bIDENT\(`
//
// This is good enough to catch the named bypass classes (RCE via
// xp_cmdshell, dynamic SQL via sp_executesql, file read via
// OPENROWSET / OPENDATASOURCE) but is NOT a full T-SQL parser.
// Statements with unusual syntax (e.g. window functions in weird
// positions, MERGE, CROSS APPLY) classify on the first keyword only.
package mssql

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

const Dialect = "mssql"

func init() {
	sqlguard.Register(&classifier{})
}

type classifier struct{}

func (classifier) Dialect() string { return Dialect }

func (c classifier) Classify(in string) (sqlguard.Classification, error) {
	if strings.TrimSpace(in) == "" {
		return sqlguard.Classification{}, fmt.Errorf("mssql parse: empty input")
	}
	stripped, err := stripCommentsAndStrings(in)
	if err != nil {
		return sqlguard.Classification{}, fmt.Errorf("mssql parse: %w", err)
	}
	parts := splitTopLevelStatements(stripped)
	if len(parts) == 0 {
		return sqlguard.Classification{}, fmt.Errorf("mssql parse: no statements")
	}

	cl := sqlguard.Classification{Dialect: Dialect, StmtCount: len(parts)}
	funcSet := map[string]struct{}{}

	// Function-call heuristic regex over the ORIGINAL input (so string
	// literals containing function-call-like text count too — we'd
	// rather over-collect for the allowlist check than miss).
	for _, fn := range collectFunctions(in) {
		funcSet[fn] = struct{}{}
	}

	for _, part := range parts {
		first, rest := firstKeyword(part)
		kind := keywordToKind(first)
		cl.TopLevelKinds = append(cl.TopLevelKinds, kind)

		// Dynamic SQL: EXEC sp_executesql, EXECUTE, sp_executesql in
		// any position, dollar-quoted-like patterns.
		if kind == sqlguard.KindExecute || kind == sqlguard.KindCall {
			cl.UsesDynamicSQL = true
		}
		if containsAnyCaseInsensitive(rest, []string{"sp_executesql"}) {
			cl.UsesDynamicSQL = true
		}

		// Shell exec primitives.
		if containsAnyCaseInsensitive(rest, []string{
			"xp_cmdshell",
			"sp_oacreate",
			"sp_oamethod",  // ole automation, common shell vector
			"sp_oadestroy", // ole automation cleanup
			"sp_oageterrorinfo",
		}) || containsAnyCaseInsensitive(first, []string{"xp_cmdshell"}) {
			cl.UsesProgram = true
		}

		// File / remote-data read primitives. These let a SELECT
		// pull data from arbitrary external sources, so we surface
		// them as UsesProgram too — the operator intent is "agent
		// must not reach outside the DB".
		if containsAnyCaseInsensitive(part, []string{
			"openrowset",
			"opendatasource",
			"bulk insert",
			"openquery",
			"openxml",                  // XML parsing primitive
			"openjson",                 // JSON parsing primitive (SQL 2016+)
			"sp_xml_preparedocument",   // XML loader, used in injection chains
			"sp_oacreate",              // OLE automation
		}) {
			cl.UsesProgram = true
		}

		// Reconfigure is the prelude to xp_cmdshell enabling:
		//   sp_configure 'show advanced options', 1; RECONFIGURE;
		//   sp_configure 'xp_cmdshell', 1; RECONFIGURE;
		// Always denied — operator privileges have no place on
		// an agent path.
		if containsAnyCaseInsensitive(part, []string{
			"sp_configure",
			"reconfigure",
		}) {
			cl.UsesDynamicSQL = true
		}

		// WAITFOR DELAY '...' is a time-based DoS primitive (also
		// used in blind-injection oracles).
		if containsAnyCaseInsensitive(part, []string{
			"waitfor delay",
			"waitfor time",
		}) {
			cl.UsesDynamicSQL = true
		}

		// Cursor declarations carry SQL bodies — treat as dynamic.
		if containsAnyCaseInsensitive(first, []string{"declare"}) &&
			containsAnyCaseInsensitive(rest, []string{"cursor"}) {
			cl.UsesDynamicSQL = true
		}

		// Linked-server / cross-server access: SELECT * FROM
		// server.db.schema.table OR [server].[db].[schema].[table].
		// We check the ORIGINAL input (not the stripped form,
		// because stripCommentsAndStrings erases [...] content).
		if hasFourPartName(in) {
			cl.UsesProgram = true
		}

		// Modifying CTE detection — same bypass class as Postgres:
		//   WITH d AS (DELETE FROM users OUTPUT deleted.* INTO ...)
		//   SELECT * FROM d
		// MSSQL CTEs use OUTPUT instead of RETURNING but the shape
		// is identical. Detect a WITH ... AS ( ... ) span whose
		// first significant keyword is DELETE/UPDATE/INSERT/MERGE.
		if kind == sqlguard.KindSelect && hasModifyingCTE(part) {
			cl.MutatesViaCTE = true
		}

		// CREATE PROCEDURE / TRIGGER carries an arbitrary body.
		if kind == sqlguard.KindCreate {
			if containsAnyCaseInsensitive(part, []string{
				"create procedure",
				"create proc ",
				"create trigger",
				"create function",
			}) {
				cl.UsesDynamicSQL = true
			}
		}
	}

	if len(funcSet) > 0 {
		cl.Functions = sortedKeys(funcSet)
		cl.FunctionsQualified = sortedKeys(funcSet)
	}
	cl.ReadOnly = cl.IsPureSelect() && !cl.UsesDynamicSQL && !cl.UsesProgram
	return cl, nil
}

func keywordToKind(kw string) sqlguard.Kind {
	switch strings.ToUpper(kw) {
	case "SELECT", "WITH":
		return sqlguard.KindSelect
	case "INSERT":
		return sqlguard.KindInsert
	case "UPDATE":
		return sqlguard.KindUpdate
	case "DELETE":
		return sqlguard.KindDelete
	case "MERGE":
		// MERGE has INSERT/UPDATE/DELETE branches — treat as UPDATE
		// for policy purposes (it's a write).
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
	case "DENY":
		// MSSQL has a DENY statement (similar to REVOKE)
		return sqlguard.KindRevoke
	case "EXEC", "EXECUTE":
		return sqlguard.KindExecute
	case "BEGIN", "COMMIT", "ROLLBACK", "SAVE":
		return sqlguard.KindTransaction
	case "SET", "DECLARE":
		return sqlguard.KindSet
	case "USE":
		return sqlguard.KindSet
	case "BACKUP", "RESTORE", "DBCC", "BULK", "WAITFOR":
		return sqlguard.KindOther
	case "PRINT", "RAISERROR", "THROW":
		return sqlguard.KindOther
	case "IF", "WHILE":
		// Control flow — defensive: treat as dynamic SQL since the
		// body can hide anything.
		return sqlguard.KindOther
	}
	return sqlguard.KindOther
}

// firstKeyword returns the first identifier-shaped token in s, and the
// remainder of s after that token. Whitespace and trailing semicolons
// are trimmed.
func firstKeyword(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	// Find end of first token (alpha/underscore run).
	i := 0
	for i < len(s) && (isAlpha(s[i]) || s[i] == '_') {
		i++
	}
	if i == 0 {
		return "", s
	}
	return s[:i], strings.TrimSpace(s[i:])
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// stripCommentsAndStrings replaces all -- comments, /* */ comments,
// '...' strings, and [...] identifiers with whitespace of the same
// length so that subsequent semicolon-splitting and keyword-spotting
// see only structural content. The byte count is preserved so
// positions remain accurate.
func stripCommentsAndStrings(s string) (string, error) {
	out := []byte(s)
	i := 0
	for i < len(out) {
		c := out[i]
		// -- line comment
		if c == '-' && i+1 < len(out) && out[i+1] == '-' {
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
			continue
		}
		// /* block comment */ (nested allowed in T-SQL)
		if c == '/' && i+1 < len(out) && out[i+1] == '*' {
			depth := 1
			out[i] = ' '
			out[i+1] = ' '
			i += 2
			for i < len(out) && depth > 0 {
				if i+1 < len(out) && out[i] == '/' && out[i+1] == '*' {
					depth++
					out[i] = ' '
					out[i+1] = ' '
					i += 2
					continue
				}
				if i+1 < len(out) && out[i] == '*' && out[i+1] == '/' {
					depth--
					out[i] = ' '
					out[i+1] = ' '
					i += 2
					continue
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			continue
		}
		// '...' string (T-SQL escapes ' by doubling)
		if c == '\'' {
			out[i] = ' '
			i++
			for i < len(out) {
				if out[i] == '\'' {
					// Could be end-of-string or doubled-quote escape.
					if i+1 < len(out) && out[i+1] == '\'' {
						out[i] = ' '
						out[i+1] = ' '
						i += 2
						continue
					}
					out[i] = ' '
					i++
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			continue
		}
		// [...] quoted identifier
		if c == '[' {
			out[i] = ' '
			i++
			for i < len(out) && out[i] != ']' {
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			if i < len(out) {
				out[i] = ' '
				i++
			}
			continue
		}
		i++
	}
	return string(out), nil
}

// splitTopLevelStatements splits a stripped T-SQL string on top-level
// semicolons. Also splits on GO batch separator (a T-SQL convention,
// not SQL — but worth recognising).
func splitTopLevelStatements(s string) []string {
	// First split on GO (on its own line, case-insensitive).
	chunks := goRegex.Split(s, -1)
	var out []string
	for _, c := range chunks {
		for _, part := range strings.Split(c, ";") {
			p := strings.TrimSpace(part)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

var goRegex = regexp.MustCompile(`(?im)^\s*GO\s*$`)

func containsAnyCaseInsensitive(s string, needles []string) bool {
	low := strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// collectFunctions finds every IDENT( in the input and returns the
// lower-cased IDENT. Heuristic — over-collects on table refs in
// subqueries — but the allowlist check works the same either way.
func collectFunctions(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range funcRegex.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		if isSQLKeyword(name) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

var funcRegex = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)

// isSQLKeyword filters out tokens that are SQL syntax (not function
// calls) but happen to be followed by an open paren — IN(...),
// VALUES(...), etc.
func isSQLKeyword(s string) bool {
	switch s {
	case "values", "in", "exists", "case", "when", "then", "else", "end",
		"if", "while", "for", "with", "as", "on", "and", "or", "not",
		"select", "from", "where", "group", "by", "having", "order",
		"union", "intersect", "except", "all", "distinct", "any", "some":
		return true
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Stable order helps tests.
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
