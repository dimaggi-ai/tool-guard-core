package sqlguard

import "strings"

// Kind names the top-level statement type of a parsed SQL string.
// The set is dialect-neutral on purpose — each backend maps its native
// parser output to this small enum.
type Kind string

const (
	KindUnknown     Kind = ""
	KindSelect      Kind = "SELECT"
	KindInsert      Kind = "INSERT"
	KindUpdate      Kind = "UPDATE"
	KindDelete      Kind = "DELETE"
	KindCreate      Kind = "CREATE"
	KindDrop        Kind = "DROP"
	KindTruncate    Kind = "TRUNCATE"
	KindAlter       Kind = "ALTER"
	KindGrant       Kind = "GRANT"
	KindRevoke      Kind = "REVOKE"
	KindDo          Kind = "DO"      // PG anonymous code block
	KindCall        Kind = "CALL"    // procedure invocation
	KindExecute     Kind = "EXECUTE" // dynamic SQL (PG / MSSQL)
	KindPrepare     Kind = "PREPARE"
	KindCopy        Kind = "COPY" // PG bulk-load (FROM/TO PROGRAM is the danger)
	KindLoad        Kind = "LOAD" // PG load shared library
	KindSet         Kind = "SET"  // SET ROLE etc.
	KindDiscard     Kind = "DISCARD"
	KindTransaction Kind = "TRANSACTION" // BEGIN/COMMIT/ROLLBACK
	KindOther       Kind = "OTHER"
)

// Classification is the dialect-neutral output of a parser. Policies
// reason about these fields only — they never see the native AST.
type Classification struct {
	// Dialect that produced this classification. Echoed for debugging
	// and audit traces.
	Dialect string `json:"dialect"`

	// StmtCount is the number of top-level statements parsed from the
	// input. A clean SELECT-only input has StmtCount == 1; smuggling via
	// "SELECT 1; DROP TABLE x" yields 2.
	StmtCount int `json:"stmt_count"`

	// TopLevelKinds lists the Kind for each top-level statement. Most
	// callers want len == 1 and TopLevelKinds[0] == KindSelect.
	TopLevelKinds []Kind `json:"top_level_kinds"`

	// Functions is the de-duplicated list of function names invoked
	// anywhere in the statement tree. Use last-name only (no schema
	// qualifier) for simple allowlist matching; the FunctionsQualified
	// slice retains the full dotted form for the operator who wants it.
	Functions          []string `json:"functions,omitempty"`
	FunctionsQualified []string `json:"functions_qualified,omitempty"`

	// UsesProgram is true when the statement reaches the shell via the
	// database engine. Postgres: COPY ... FROM/TO PROGRAM. MSSQL:
	// xp_cmdshell (treated as a function call, also captured here for
	// convenience). MySQL: not directly reachable; always false.
	UsesProgram bool `json:"uses_program,omitempty"`

	// UsesDynamicSQL is true when the statement constructs and executes
	// SQL at runtime. Covers Postgres DO blocks, EXECUTE, PREPARE, and
	// the MSSQL sp_executesql shape.
	UsesDynamicSQL bool `json:"uses_dynamic_sql,omitempty"`

	// ReadOnly is the dialect's own opinion of whether the statement
	// only reads. Populated when the parser exposes it (SQLite does;
	// Postgres and MySQL we derive from Kind).
	ReadOnly bool `json:"read_only,omitempty"`

	// MutatesViaCTE flags the modifying-CTE pattern:
	//   WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d
	// The top-level statement IS a SELECT (so plain "top_level_kinds:
	// [SELECT]" lets it through), but a CTE inside that SELECT writes
	// to the database during execution. Postgres specifically allows
	// INSERT/UPDATE/DELETE/MERGE statements as data-modifying CTEs.
	// SQLite + MySQL don't support this, but we expose the field on
	// the common shape so policies are uniform.
	MutatesViaCTE bool `json:"mutates_via_cte,omitempty"`

	// Tables names every table referenced anywhere in the statement —
	// from FROM, JOIN, INTO, USING, TABLE-shorthand, and DML targets.
	// Schema-qualified names appear as schema.table; unqualified just
	// table. Use AllowedTables / DeniedTables in SQLRequire to gate.
	// Catches `TABLE pg_authid` (a single-word SELECT shorthand that
	// would otherwise classify as a clean SELECT) and any
	// information_schema/pg_catalog probe.
	Tables []string `json:"tables,omitempty"`
}

// HasDeniedTable reports whether any referenced table starts with a
// denied prefix (case-insensitive). Prefix match is intentional so
// "pg_" denies all pg_catalog tables, "secrets." denies any schema.
func (c *Classification) HasDeniedTable(denied []string) (string, bool) {
	if len(denied) == 0 {
		return "", false
	}
	for _, t := range c.Tables {
		lt := strings.ToLower(t)
		for _, d := range denied {
			ld := strings.ToLower(d)
			if strings.HasPrefix(lt, ld) {
				return t, true
			}
		}
	}
	return "", false
}

// HasTableOutsideAllowed reports whether any referenced table is NOT
// in the allowed list. Allowed entries are exact-match (case-insensitive),
// schema-qualified or not (operator's choice).
func (c *Classification) HasTableOutsideAllowed(allowed []string) (string, bool) {
	if len(allowed) == 0 {
		return "", false
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowSet[strings.ToLower(a)] = struct{}{}
	}
	for _, t := range c.Tables {
		if _, ok := allowSet[strings.ToLower(t)]; !ok {
			return t, true
		}
	}
	return "", false
}

// IsPureSelect returns true when there is exactly one top-level
// statement and it is a SELECT.
func (c *Classification) IsPureSelect() bool {
	return c.StmtCount == 1 && len(c.TopLevelKinds) == 1 && c.TopLevelKinds[0] == KindSelect
}

// HasDisallowedFunction reports whether any function call in the
// statement is NOT in the allowlist. The allowlist match is on
// unqualified function names (last dotted component); pass an empty
// allowlist to skip the check.
func (c *Classification) HasDisallowedFunction(allow []string) (string, bool) {
	if len(allow) == 0 {
		return "", false
	}
	set := make(map[string]struct{}, len(allow))
	for _, a := range allow {
		set[a] = struct{}{}
	}
	for _, fn := range c.Functions {
		if _, ok := set[fn]; !ok {
			return fn, true
		}
	}
	return "", false
}
