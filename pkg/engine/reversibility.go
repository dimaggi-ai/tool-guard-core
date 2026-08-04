package engine

import (
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

// ReversibilityClass describes the apparent reversibility of a tool call from
// its declared name, group, and parameter structure. Policies can use it as an
// input to an irreversibility floor (see policies/irreversibility_floor.yaml).
//
// The value is exposed to policy rules as the flattened condition field
// "reversibility" (see FlattenEnvelope), so an operator writes
// {field: reversibility, operator: eq, value: irreversible} exactly like
// any other leaf.
type ReversibilityClass string

const (
	// Reversible: no lasting effect, or trivially undone with a single
	// inverse operation at no cost — reads/list/get, add-label, create-draft.
	Reversible ReversibilityClass = "reversible"

	// Recoverable: undoable, but only with effort, cost, or a restore
	// window — for example, a file overwrite or scoped SQL UPDATE/DELETE.
	Recoverable ReversibilityClass = "recoverable"

	// Irreversible: cannot be undone by any ordinary means — a settled
	// payment/wire/transfer/refund, account or data destruction, a
	// production deploy/publish, physical actuation, DROP/TRUNCATE or an
	// unscoped DELETE, rm -rf. These are the actions the floor gates.
	Irreversible ReversibilityClass = "irreversible"

	// Unknown: the visible structure is insufficient to classify the effect.
	// It remains distinct from Reversible so policies can handle uncertainty
	// explicitly; the shipped floor escalates it.
	Unknown ReversibilityClass = "unknown"
)

// reversibilityRank orders the classes by how strongly the floor GATES them,
// so signals from different parts of a call merge by keeping the most-gating
// (worst) one. The order mirrors the floor's action exactly:
//
//	Irreversible (escalate, definitely unsafe)
//	  > Unknown   (escalate, cannot be certified safe)
//	  > Recoverable (allow, undoable with effort)
//	  > Reversible  (allow, trivially safe)
//
// Unknown outranks BOTH allow-classes on purpose: an unrecognized component is
// escalated, so in a merge it must beat a Recoverable or Reversible signal from
// another axis — worst(Unknown, Recoverable) = Unknown. (Whether an
// UNINFORMATIVE tool NAME should be allowed to override the parsed action is a
// separate question, handled in ClassifyReversibility, not here.)
func reversibilityRank(c ReversibilityClass) int {
	switch c {
	case Irreversible:
		return 3
	case Unknown:
		return 2
	case Recoverable:
		return 1
	case Reversible:
		return 0
	default:
		return 2 // any unexpected value is treated as Unknown (caution)
	}
}

// worst returns the higher-ranked (more gating) of two classes.
func worst(a, b ReversibilityClass) ReversibilityClass {
	if reversibilityRank(b) > reversibilityRank(a) {
		return b
	}
	return a
}

// ClassifyReversibility deterministically classifies a tool call from its
// envelope. It performs no network calls or LLM inference; the class is derived
// only from tool_name, tool_group, and parameter structure.
//
// Two kinds of signal are combined:
//
//   - Authoritative parameter surfaces — SQL, command/cmd, and argv — describe
//     the actual action. When present they decide the
//     class, and an UNINFORMATIVE tool name (one that matched nothing, i.e.
//     Unknown) does not override them: a tool literally named "bash" running
//     `ls` is Reversible, running `rm -rf /` is Irreversible. A name that DID
//     carry a signal (a read verb, a money group, "deploy") is still merged by
//     worst-wins, so a deploy tool that also shells out stays gated.
//   - The tool name/group otherwise, plus the outbound HTTP method (GET/HEAD →
//     Reversible; mutating and unrecognized methods → Unknown). A method cannot
//     prove that its endpoint has an undo path, so generic HTTP mutations stay
//     fail-safe unless a future trusted endpoint classifier supplies that proof.
//
// When nothing is recognized anywhere it returns Unknown. The exact mappings
// live in the tables below.
func ClassifyReversibility(env domain.ActionEnvelope) ReversibilityClass {
	nameClass := nameGroupReversibility(env.ToolName, env.ToolGroup)
	params := parseParams(env.Parameters)

	// Authoritative parameter surfaces (the real action being taken).
	authSurface := Reversible
	hasAuth := false
	consider := func(c ReversibilityClass) {
		authSurface = worst(authSurface, c)
		hasAuth = true
	}
	// Only parameters.sql is consulted — the field sql_classify keys off — so a
	// natural-language "query" param on a search tool is never misread as SQL.
	if sql := firstString(params, "sql"); sql != "" {
		consider(sqlReversibility(sql))
	}
	// command/cmd is itself an execution surface. Parse it regardless of the
	// declared tool name so an MCP server cannot hide `rm -rf` behind `get_*`.
	if cmd := firstString(params, "command", "cmd"); cmd != "" {
		consider(shellStringReversibility(cmd))
	}
	if argv, ok := normalizeArgv(params["argv"]); ok && len(argv) > 0 {
		consider(argvReversibility(argv))
	}
	// Outbound HTTP: a URL is an execution surface. A missing or blank method is
	// Unknown rather than evidence that the request is safe.
	if firstString(params, "url") != "" {
		consider(httpMethodReversibility(firstString(params, "method")))
	}

	if hasAuth {
		class := authSurface
		// Respect a name that carried a real signal; ignore a name that told us
		// nothing (Unknown) so it cannot mask the parsed action.
		if nameClass != Unknown {
			class = worst(class, nameClass)
		}
		return class
	}
	return nameClass
}

// ── tool_name / tool_group mapping tables ───────────────────────────────
//
// These are the primary, auditable signal. Matching is on the LOWER-CASED,
// separator-split tokens of the tool name (so "issue_refund", "issueRefund",
// and "issue-refund" tokenize identically) plus the whole normalized name
// and the raw tool group. The ladder in nameGroupReversibility fixes the
// precedence; read the comment there for why the order is what it is.

// reversibleFirstVerbs: a tool whose FIRST token is one of these is a read /
// observation — it only inspects state and can be re-run freely. Matching on
// the first token (not any token) keeps "get_payment_status" a read while
// letting "issue_refund" fall through to the money-movement tables.
var reversibleFirstVerbs = map[string]bool{
	"read": true, "get": true, "list": true, "describe": true, "search": true,
	"query": true, "view": true, "lookup": true, "show": true, "count": true,
	"preview": true, "head": true, "inspect": true, "find": true, "fetch": true,
	"retrieve": true, "download": true, "export": true, "summarize": true,
	"analyze": true, "check": true, "status": true, "ping": true, "peek": true,
}

// reversibleExactNames: specific whole actions that are trivially undone.
// Checked before the token tables so their (otherwise ambiguous) verbs
// like "create"/"remove" do not pull them into Recoverable.
var reversibleExactNames = map[string]bool{
	"add_label": true, "remove_label": true, "apply_label": true,
	"create_draft": true, "save_draft": true, "add_tag": true, "remove_tag": true,
}

// irreversibleFirstVerbs: a tool whose FIRST token is one of these commits an
// effect that cannot be undone (money leaves, code ships, hardware moves,
// a message is sent).
var irreversibleFirstVerbs = map[string]bool{
	// money movement
	"wire": true, "transfer": true, "remit": true, "disburse": true, "pay": true,
	// release / deploy
	"deploy": true, "publish": true, "release": true, "rollout": true,
	// destruction / physical actuation / irrevocable comms
	"purge": true, "wipe": true, "detonate": true, "launch": true, "fire": true,
	"dispense": true, "actuate": true, "send": true, "broadcast": true,
	"shred": true,
}

// irreversibleAnyToken: object nouns that mark money movement no matter where
// they sit in the name (e.g. "process_payout"). Deliberately excludes broad
// words like "payment" that also appear in read tools ("get_payment_status")
// — those are covered by the money-movement groups/verbs instead. Because the
// read-verb check runs first, "get_refund_status" is still a read.
var irreversibleAnyToken = map[string]bool{
	"payout": true, "chargeback": true, "refund": true, "remittance": true,
	"disbursement": true, "payroll": true, "wire": true,
}

// irreversibleExactNames: named actions with no undo path.
var irreversibleExactNames = map[string]bool{
	"delete_account": true, "close_account": true, "deactivate_account": true,
	"delete_user": true, "delete_customer": true, "drop_database": true,
	"drop_table": true, "factory_reset": true, "format_disk": true,
	"wipe_disk": true, "erase_disk": true, "delete_project": true,
	"delete_repository": true, "terminate_instance": true,
	"destroy_environment": true,
	// Whole-datastore / resource destruction. The first-verb "delete" would
	// otherwise grade these Recoverable; naming the object makes clear there is
	// no ordinary undo (the exact-name table is checked first in the ladder).
	"delete_database": true, "delete_databases": true, "delete_table": true,
	"delete_tables": true, "delete_schema": true, "delete_namespace": true,
	"delete_cluster": true, "delete_volume": true, "delete_bucket": true,
	"delete_backup": true, "delete_snapshot": true, "delete_disk": true,
	"delete_production_data": true, "purge_database": true, "purge_data": true,
	"destroy_database": true, "destroy_cluster": true, "destroy_volume": true,
}

// irreversibleReleaseTokens mark a production release / deploy no matter where
// they sit in the name ("trigger_deploy", "run_release"). Like the money
// nouns, they are checked AFTER the read-verb short-circuit, so
// "get_deployment_status" / "list_releases" stay reversible reads.
var irreversibleReleaseTokens = map[string]bool{
	"deploy": true, "deployment": true, "redeploy": true,
	"publish": true, "release": true, "rollout": true,
}

// irreversibleGroups: whole tool groups whose members are irreversible by
// nature. "monetary_outflow" is the group the repo's refund tools ship with.
var irreversibleGroups = map[string]bool{
	"payments": true, "payment": true, "money_movement": true,
	"money_transfer": true, "monetary_outflow": true, "wire_transfer": true,
	"banking": true, "actuation": true, "physical_actuation": true,
	"robotics": true, "deployment": true, "release": true, "releases": true,
}

// recoverableFirstVerbs: state-changing verbs whose effect can be restored
// with effort (from a backup, VCS, or by re-creating the resource).
var recoverableFirstVerbs = map[string]bool{
	"update": true, "modify": true, "edit": true, "write": true, "overwrite": true,
	"replace": true, "set": true, "patch": true, "upload": true, "rename": true,
	"move": true, "cancel": true, "archive": true, "disable": true, "suspend": true,
	"revoke": true, "unpublish": true, "downgrade": true, "deactivate": true,
	"create": true, "add": true, "insert": true, "save": true, "put": true,
	"sync": true, "apply": true, "tag": true, "label": true, "assign": true,
	"close": true, "remove": true, "clear": true, "reset": true, "delete": true,
}

// destructiveFirstVerbs + destructiveResourceNouns: a first-position verb from
// the first set acting on any token from the second is irreversible destruction
// of a durable store (covers singular and plural, so the exact-name table need
// not enumerate every form).
var destructiveFirstVerbs = map[string]bool{
	"delete": true, "drop": true, "destroy": true, "purge": true, "wipe": true,
	"erase": true, "truncate": true, "terminate": true, "deprovision": true,
	"teardown": true, "obliterate": true,
}

// Durable datastore/infrastructure nouns (singular + plural). Record-type
// singulars (user/account/customer) are NOT here to avoid over-escalating
// record-level deletes like delete_user_session; the whole-entity singular
// forms (delete_user, delete_account, delete_customer) live in
// irreversibleExactNames, and the unambiguous mass plurals are included here.
var destructiveResourceNouns = map[string]bool{
	"database": true, "databases": true, "table": true, "tables": true,
	"schema": true, "schemas": true, "namespace": true, "namespaces": true,
	"cluster": true, "clusters": true, "volume": true, "volumes": true,
	"bucket": true, "buckets": true, "backup": true, "backups": true,
	"snapshot": true, "snapshots": true, "disk": true, "disks": true,
	"partition": true, "partitions": true, "tablespace": true, "tablespaces": true,
	"keyspace": true, "keyspaces": true, "collection": true, "collections": true,
	"index": true, "indexes": true, "indices": true, "repository": true,
	"repositories": true, "project": true, "projects": true, "instance": true,
	"instances": true, "environment": true, "environments": true,
	"accounts": true, "users": true, "customers": true,
}

// recoverableGroups: write surfaces that are recoverable in aggregate (a
// destructive member is escalated by the parameter-shape signals instead).
var recoverableGroups = map[string]bool{
	"filesystem_writes": true, "file_writes": true, "database_writes": true,
	"storage_writes": true, "content_writes": true,
}

// nameGroupReversibility classifies from the tool name and group alone.
//
// The ladder order encodes the precedence decisions:
//  1. exact irreversible names win (most specific, most dangerous);
//  2. exact reversible names next (so their ambiguous verbs don't demote them);
//  3. a read verb in FIRST position wins over object nouns and groups, so a
//     "get_*"/"list_*" query is never gated as a write;
//  4. money-movement group / noun / verb → Irreversible;
//  5. recoverable verb / group → Recoverable;
//  6. otherwise Unknown (fail-safe — not silently Reversible).
func nameGroupReversibility(toolName, toolGroup string) ReversibilityClass {
	normName := normalizeName(toolName)
	group := strings.ToLower(strings.TrimSpace(toolGroup))
	toks := lowerTokens(toolName)
	first := ""
	if len(toks) > 0 {
		first = toks[0]
	}

	if irreversibleExactNames[normName] {
		return Irreversible
	}
	if reversibleExactNames[normName] {
		return Reversible
	}
	if reversibleFirstVerbs[first] {
		return Reversible
	}
	if irreversibleGroups[group] {
		return Irreversible
	}
	for _, t := range toks {
		if irreversibleAnyToken[t] || irreversibleReleaseTokens[t] {
			return Irreversible
		}
	}
	// A destructive verb acting on a durable datastore/resource noun is
	// irreversible, in singular OR plural form (delete_database, delete_backups,
	// drop_tables, purge_data). This generalizes the exact-name table so a
	// plural or a new combination is not silently graded Recoverable via the
	// `delete` recoverable-verb fallback.
	if destructiveFirstVerbs[first] {
		for _, t := range toks {
			if destructiveResourceNouns[t] {
				return Irreversible
			}
		}
	}
	if irreversibleFirstVerbs[first] {
		return Irreversible
	}
	if recoverableFirstVerbs[first] {
		return Recoverable
	}
	if recoverableGroups[group] {
		return Recoverable
	}
	return Unknown
}

// normalizeName lower-cases the tool name and joins its tokens with '_' so a
// name written as "delete-account", "deleteAccount", or "delete_account" all
// match the same exact-name table key.
func normalizeName(s string) string {
	return strings.Join(lowerTokens(s), "_")
}

// lowerTokens splits an identifier into lower-cased word tokens on any
// non-alphanumeric separator AND on camelCase boundaries, so "issue_refund",
// "issue-refund", and "issueRefund" all yield [issue refund].
func lowerTokens(s string) []string {
	var toks []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for i, r := range s {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.' || r == '/' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(prev) || unicode.IsDigit(prev)):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return toks
}

// ── SQL parameter shape ─────────────────────────────────────────────────

// sqlReversibility classifies a SQL statement by its top-level kind. It
// reuses the sqlguard classifier (postgres / mysql / sqlite / mssql) when a
// dialect parser is linked into the binary; if none is, or the statement
// parses in no linked dialect, it falls back to a conservative keyword scan.
// Either way, an unrecognized statement returns Unknown (caution), never
// Reversible.
func sqlReversibility(sql string) ReversibilityClass {
	// Analyse each statement INDEPENDENTLY, splitting only on `;` that is real
	// code (not inside a string, a quoted identifier, a dollar-quoted body, or a
	// comment). Per-statement analysis is what keeps a sibling statement's WHERE
	// from making an unscoped DELETE look scoped
	// (`DELETE FROM t; SELECT * FROM u WHERE x` — the DELETE has no WHERE).
	stmts := splitSQLStatements(sql)
	class := Reversible
	sawStatement := false
	for _, st := range stmts {
		if strings.TrimSpace(st) == "" {
			continue
		}
		sawStatement = true
		class = worst(class, sqlStatementReversibility(st))
	}
	if !sawStatement {
		return Unknown // nothing to classify → fail-safe
	}
	return class
}

// sqlStatementReversibility classifies ONE SQL statement. The keyword scan and
// the WHERE/tautology checks run on the statement's SKELETON — a length-
// preserving copy with comment and string-literal CONTENT blanked to spaces —
// so a destructive keyword or a WHERE token that appears only inside a quoted
// value (`SELECT ... WHERE title = 'How to DROP a table'`, an unscoped DELETE
// whose data merely contains the word WHERE) can neither over-gate a read nor
// fake-scope a delete. The real dialect parser still sees the original text. It
// takes the worst of the two so a destructive verb the parser did not surface
// as a top-level kind (a data-modifying CTE whose MutatesViaCTE flag a dialect
// missed) is still caught by the keyword path and never auto-allowed.
func sqlStatementReversibility(stmt string) ReversibilityClass {
	view := sqlSkeleton(stmt)
	kwd := sqlKeywordFallback(view)
	// The linked dialect parsers do not all understand Postgres dollar-quoting
	// or MySQL backtick identifiers, and would mislex a `$$…$$` body or an
	// apostrophe inside a `backtick` identifier. Feed the parser a sanitized
	// copy where those constructs are replaced by ordinary tokens, so it sees
	// valid SQL and its structural signals (top-level kind, MutatesViaCTE) are
	// reliable. The length-preserving skeleton (used for the WHERE test) is a
	// separate view; only the parser gets this non-length-preserving copy.
	cl, ok := classifySQL(sqlForParser(stmt))
	if !ok || len(cl.TopLevelKinds) == 0 {
		return kwd
	}
	class := Reversible
	if cl.MutatesViaCTE {
		class = worst(class, Irreversible)
	}
	for _, k := range cl.TopLevelKinds {
		class = worst(class, sqlKindReversibility(k, view))
	}
	return worst(class, kwd)
}

// classifySQL runs the SQL through every linked sqlguard dialect (the list is
// returned sorted, so the result is deterministic) and returns the first
// classification that parses. Returns ok=false when no dialect is linked or
// none parses the statement.
func classifySQL(sql string) (sqlguard.Classification, bool) {
	for _, dialect := range sqlguard.Dialects() {
		if cl, err := sqlguard.Classify(dialect, sql); err == nil {
			return cl, true
		}
	}
	return sqlguard.Classification{}, false
}

// sqlKindReversibility maps a parsed top-level statement kind to a class.
//
//   - DROP / TRUNCATE            → Irreversible (schema/data destruction)
//   - DELETE / UPDATE, unscoped
//     or tautological WHERE       → Irreversible (whole-relation wipe/overwrite)
//   - DELETE / UPDATE ... WHERE   → Recoverable  (scoped; restorable from backup)
//   - INSERT / CREATE / ALTER /
//     GRANT / REVOKE / SET        → Recoverable  (undoable with effort)
//   - SELECT                      → Reversible   (read-only)
//   - anything else               → Unknown      (fail-safe)
//
// `sql` here is a SINGLE statement's SKELETON (sqlReversibility splits first,
// and sqlStatementReversibility passes the literal/comment-blanked view), so
// the WHERE test can neither pick up a sibling statement's clause nor be fooled
// by the word WHERE sitting inside a string literal.
func sqlKindReversibility(k sqlguard.Kind, sql string) ReversibilityClass {
	switch k {
	case sqlguard.KindSelect:
		return Reversible
	case sqlguard.KindDrop, sqlguard.KindTruncate:
		return Irreversible
	case sqlguard.KindDelete, sqlguard.KindUpdate:
		// An UPDATE with no (or a tautological) WHERE overwrites every row's
		// prior values just as an unscoped DELETE erases every row — both are
		// whole-relation and irreversible without an external backup.
		return scopedWriteClass(sql)
	case sqlguard.KindInsert, sqlguard.KindCreate,
		sqlguard.KindAlter, sqlguard.KindGrant, sqlguard.KindRevoke, sqlguard.KindSet:
		return Recoverable
	default:
		return Unknown
	}
}

// sqlKeywordFallback is the dialect-free path used when no sqlguard parser is
// linked. It classifies by the destructive keywords present as whole words.
// It shares the DROP/TRUNCATE/DELETE/UPDATE/... → class mapping with
// sqlKindReversibility so the two paths agree.
func sqlKeywordFallback(sql string) ReversibilityClass {
	words := sqlWordSet(sql)
	switch {
	case words["DROP"] || words["TRUNCATE"]:
		return Irreversible
	case words["DELETE"] || words["UPDATE"]:
		return scopedWriteClass(sql)
	case words["INSERT"] || words["ALTER"] ||
		words["CREATE"] || words["GRANT"] || words["REVOKE"]:
		return Recoverable
	case words["SELECT"]:
		return Reversible
	default:
		return Unknown
	}
}

// scopedWriteClass grades the DELETE/UPDATE writes in a statement skeleton. It
// is verb- and paren-depth-aware so a WHERE that does NOT belong to the write
// cannot fake-scope it: a leading statement's WHERE in a no-semicolon T-SQL
// batch (`SELECT ... WHERE x DELETE FROM t`), or a WHERE buried in a subquery
// of the SET clause, does not count. Each DELETE/UPDATE at top paren-depth is
// scoped only by a WHERE at top depth that appears AFTER the verb and before
// the next top-depth statement-start keyword; a tautological WHERE (1=1) does
// not scope. The worst class across all writes in the skeleton is returned.
func scopedWriteClass(view string) ReversibilityClass {
	words := sqlWordsWithDepth(view)
	cls := Reversible
	sawWrite := false
	for i := 0; i < len(words); i++ {
		if words[i].depth != 0 || (words[i].up != "DELETE" && words[i].up != "UPDATE") {
			continue
		}
		sawWrite = true
		clauseEnd := len(view)
		whereStart := -1
		for j := i + 1; j < len(words); j++ {
			if words[j].depth == 0 && isStmtStartKeyword(words[j].up) {
				clauseEnd = words[j].start
				break
			}
			if words[j].depth == 0 && words[j].up == "WHERE" && whereStart < 0 {
				whereStart = words[j].start
			}
		}
		if whereStart >= 0 && !whereIsTautology(view[whereStart:clauseEnd]) {
			cls = worst(cls, Recoverable)
		} else {
			cls = worst(cls, Irreversible)
		}
	}
	if !sawWrite {
		return Recoverable // caller only invokes when a write verb is present
	}
	return cls
}

// sqlWord is one alnum/underscore token of a SQL skeleton with its upper-case
// form, byte offset, and parenthesis nesting depth.
type sqlWord struct {
	up    string
	start int
	depth int
}

// sqlWordsWithDepth tokenizes a skeleton (literals already blanked) into words,
// tracking `(`/`)` nesting so a subquery's tokens carry depth > 0.
func sqlWordsWithDepth(view string) []sqlWord {
	var out []sqlWord
	depth := 0
	i, n := 0, len(view)
	for i < n {
		c := view[i]
		switch {
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			i++
		case isSQLWordByte(c):
			j := i
			for j < n && isSQLWordByte(view[j]) {
				j++
			}
			out = append(out, sqlWord{up: asciiUpper(view[i:j]), start: i, depth: depth})
			i = j
		default:
			i++
		}
	}
	return out
}

// isStmtStartKeyword reports whether w begins a new top-level SQL statement, so
// it bounds a preceding write's clause (needed because T-SQL allows batches
// with no `;` between statements). Clause-internal keywords (FROM, SET, WHERE,
// JOIN, VALUES, ...) are deliberately excluded.
func isStmtStartKeyword(w string) bool {
	switch w {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "MERGE",
		"CREATE", "ALTER", "GRANT", "REVOKE", "EXEC", "EXECUTE", "CALL",
		"WITH", "REPLACE", "DECLARE":
		return true
	}
	return false
}

// whereIsTautology reports whether a WHERE clause fails to scope the write by
// DATA, so the write hits the whole relation. The robust test is not "is the
// predicate always true" (that is SAT-hard and endless: 1=1, 1<2, NOT 1=2,
// 2 BETWEEN 1 AND 3, 1 IN (1), 1=1 OR true, ...) but "does the predicate
// reference a column at all". A predicate built only from constants and
// operators/keywords selects every row (always-true) or none (always-false);
// either way it is not row-scoped, so the write is treated as whole-relation.
// A predicate that references any column is treated as genuinely scoping, with
// one exception kept from the literal case: an identical-sides comparison
// (col = col, id <= id) is always-true even though it names a column.
func whereIsTautology(stmt string) bool {
	up := asciiUpper(stmt)
	idx := indexSQLWord(up, "WHERE")
	if idx < 0 {
		return false
	}
	return predicateIsWholeRelation(cutAtSQLClause(stmt[idx+len("WHERE"):]))
}

// predicateIsWholeRelation reports whether a WHERE predicate selects the whole
// relation (so a DELETE/UPDATE is not row-scoped). True when:
//   - any top-level OR disjunct is always-true (X OR 1=1 is always true), OR
//   - the predicate references no column at all (constant-only => whole
//     relation or none, over-approximated to whole), OR
//   - it is an identical-sides comparison (col = col).
func predicateIsWholeRelation(body string) bool {
	if predicateAlwaysTrue(body) {
		return true
	}
	// A constant-only predicate references no column, so it is always-true or
	// always-false: either way it does not row-scope the write (whole relation
	// or none), over-approximated to whole.
	return !predicateReferencesColumn(body)
}

// predicateAlwaysTrue reports whether a predicate is a tautology. It decomposes
// top-level boolean structure — OR (any disjunct always-true) and AND (all
// conjuncts always-true) — before the atom test (constant always-true, or an
// identical-sides comparison col = col). This catches nested forms like
// `col=col AND 1=1`, `(col=col AND 1=1) OR x=5`, `1=1 OR true`.
func predicateAlwaysTrue(p string) bool {
	p = trimPredicate(p) // unwrap a fully-parenthesized (X) so its OR/AND is top-level
	if ors := splitTopLevelOr(p); len(ors) > 1 {
		for _, d := range ors {
			if predicateAlwaysTrue(d) {
				return true
			}
		}
		return false
	}
	if ands := splitTopLevelAnd(p); len(ands) > 1 {
		for _, c := range ands {
			if !predicateAlwaysTrue(c) {
				return false
			}
		}
		return true
	}
	if !predicateReferencesColumn(p) {
		return constPredicateTrue(p)
	}
	return identicalSidesAlwaysTrue(p)
}

// splitTopLevelAnd splits a predicate on the word AND at paren-depth 0. (A
// BETWEEN's internal AND still splits, but its fragments reference a column
// when scoped, so the column-reference check keeps a scoped BETWEEN safe.)
func splitTopLevelAnd(body string) []string {
	words := sqlWordsWithDepth(body)
	var parts []string
	start := 0
	for _, w := range words {
		if w.depth == 0 && w.up == "AND" {
			parts = append(parts, body[start:w.start])
			start = w.start + 3
		}
	}
	return append(parts, body[start:])
}

// identicalSidesAlwaysTrue reports whether body is `A OP A` with OP in {=,<=,>=}.
func identicalSidesAlwaysTrue(body string) bool {
	b := trimPredicate(body)
	if op, l, r, ok := splitComparison(b); ok {
		l, r = strings.TrimSpace(l), strings.TrimSpace(r)
		if l != "" && l == r {
			switch op {
			case "=", "<=", ">=":
				return true
			}
		}
	}
	return false
}

// constPredicateTrue evaluates a constant-only predicate to always-true where it
// can (true/1, integer comparisons, identical sides, differing-literal !=), and
// otherwise (BETWEEN/IN/NOT and other un-evaluable constant forms) returns true
// as the SAFE over-approximation for the OR-disjunct test.
func constPredicateTrue(d string) bool {
	b := trimPredicate(d)
	switch strings.ToLower(b) {
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	if op, l, r, ok := splitComparison(b); ok {
		l, r = strings.TrimSpace(l), strings.TrimSpace(r)
		if li, e1 := strconv.Atoi(l); e1 == nil {
			if ri, e2 := strconv.Atoi(r); e2 == nil {
				switch op {
				case "=":
					return li == ri
				case "<>", "!=":
					return li != ri
				case "<":
					return li < ri
				case ">":
					return li > ri
				case "<=":
					return li <= ri
				case ">=":
					return li >= ri
				}
			}
		}
		if l == r && l != "" {
			switch op {
			case "=", "<=", ">=":
				return true
			default:
				return false
			}
		}
		if (op == "<>" || op == "!=") && l != r {
			return true // two different constants are always unequal
		}
	}
	return true // un-evaluable constant predicate: over-approximate to whole-relation
}

// splitTopLevelOr splits a predicate on the word OR at paren-depth 0.
func splitTopLevelOr(body string) []string {
	words := sqlWordsWithDepth(body)
	var parts []string
	start := 0
	for _, w := range words {
		if w.depth == 0 && w.up == "OR" {
			parts = append(parts, body[start:w.start])
			start = w.start + 2
		}
	}
	return append(parts, body[start:])
}

func trimPredicate(body string) string {
	b := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), ";"))
	// Strip outer parens only when the leading '(' matches the FINAL ')', so a
	// non-wrapping pair like `(a) OR (b)` is left intact (naively stripping it
	// would produce the unbalanced `a) OR (b`).
	for len(b) >= 2 && b[0] == '(' && b[len(b)-1] == ')' && parenWrapsWhole(b) {
		b = strings.TrimSpace(b[1 : len(b)-1])
	}
	return b
}

// parenWrapsWhole reports whether the '(' at index 0 has its matching ')' at the
// final index (so the parens wrap the entire expression). Operates on a
// skeleton view where parens inside string literals are already blanked.
func parenWrapsWhole(b string) bool {
	depth := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i == len(b)-1
			}
		}
	}
	return false
}

// predicateReferencesColumn reports whether a WHERE-clause body contains any
// column reference: an identifier token that is not a numeric literal and not a
// SQL keyword/operator word. String literals are already blanked in the
// skeleton (so 'x' contributes no token), numbers are constants, and logical /
// comparison keywords are excluded, so what remains is a column (or a function
// name, treated conservatively as a reference => scoped).
func predicateReferencesColumn(body string) bool {
	for _, w := range sqlWordsWithDepth(body) {
		t := w.up
		if t == "" || (t[0] >= '0' && t[0] <= '9') {
			continue // numeric literal token
		}
		if sqlNonColumnKeyword[t] {
			continue
		}
		return true
	}
	return false
}

// sqlNonColumnKeyword lists the logical / comparison / query keywords that can
// appear in a WHERE predicate but are NOT column references. Deliberately does
// NOT include ambiguous words that are commonly column names (type, status,
// data, user, ...), so a real column is never mistaken for a keyword.
var sqlNonColumnKeyword = map[string]bool{
	"AND": true, "OR": true, "NOT": true, "NULL": true, "TRUE": true,
	"FALSE": true, "IS": true, "IN": true, "LIKE": true, "ILIKE": true,
	"BETWEEN": true, "EXISTS": true, "ANY": true, "ALL": true, "SOME": true,
	"CASE": true, "WHEN": true, "THEN": true, "ELSE": true, "END": true,
	"CAST": true, "AS": true, "DISTINCT": true, "ESCAPE": true, "COLLATE": true,
	"SELECT": true, "FROM": true, "WHERE": true, "GROUP": true, "ORDER": true,
	"BY": true, "HAVING": true, "LIMIT": true, "OFFSET": true, "UNION": true,
	"INTERSECT": true, "EXCEPT": true, "ON": true, "USING": true, "JOIN": true,
	"INNER": true, "LEFT": true, "RIGHT": true, "OUTER": true, "FULL": true,
	"CROSS": true, "NATURAL": true, "SYMMETRIC": true, "SIMILAR": true,
}

// splitComparison splits `LHS OP RHS` on the first top-level comparison
// operator, longest-match first so <= / >= / <> / != win over their prefixes.
func splitComparison(b string) (op, l, r string, ok bool) {
	for _, o := range []string{"<=", ">=", "<>", "!=", "=", "<", ">"} {
		if i := strings.Index(b, o); i > 0 {
			return o, b[:i], b[i+len(o):], true
		}
	}
	return "", "", "", false
}

// sqlSkeleton returns a length-preserving copy of sql with the CONTENT of every
// comment (-- line, # line, /* */ block) and every literal/quoted-identifier
// replaced by spaces, while the delimiters and all real code are kept in place.
// Covered: single-quoted string, double-quoted identifier, MySQL `backtick`
// identifier, MSSQL/SQLite [bracket] identifier, and `$tag$ ... $tag$`
// dollar-quoted body. Keyword scanning, `;` statement
// splitting, and WHERE detection all run on the skeleton, so nothing inside a
// literal or comment can hide a verb, fake a WHERE, or split a statement.
// Escapes are handled so a quote does not close early: doubled single quotes,
// doubled double quotes, doubled backticks, and MySQL backslash escapes are
// consumed as content.
// Malformed / unterminated spans run to end-of-input (safe: the whole tail
// becomes literal content, and the closing delimiter is absent so nothing after
// it is misread). Byte length is always preserved.
func sqlSkeleton(sql string) string {
	b := []byte(sql)
	n := len(b)
	out := make([]byte, n)
	copy(out, b)
	blank := func(a, z int) {
		for k := a; k < z && k < n; k++ {
			if b[k] != '\n' {
				out[k] = ' '
			}
		}
	}
	i := 0
	for i < n {
		c := b[i]
		switch {
		case c == '-' && i+1 < n && b[i+1] == '-':
			j := i + 2
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '#':
			// MySQL '#' line comment. Blanking to end-of-line fixes the
			// under-gate where a `#`-commented WHERE fake-scopes a DELETE. It
			// can over-gate an MSSQL `#temp` table reference (there '#' starts
			// an identifier, not a comment), but that is the safe direction
			// (escalate), not an auto-allow.
			j := i + 1
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < n && b[i+1] == '*':
			// NESTING block comment (Postgres and the lite tokenizer nest; MySQL
			// does not). Counting depth is the safe reading: it blanks the whole
			// nested region, so a WHERE that Postgres treats as commented-out
			// cannot survive to fake-scope a write. (For non-nesting dialects
			// this can over-blank, which only over-escalates.)
			j := i + 2
			depth := 1
			for j < n && depth > 0 {
				if j+1 < n && b[j] == '/' && b[j+1] == '*' {
					depth++
					j += 2
				} else if j+1 < n && b[j] == '*' && b[j+1] == '/' {
					depth--
					j += 2
				} else {
					j++
				}
			}
			blank(i, j) // j is past the final */, or n if unterminated
			i = j
		case c == '\'' || c == '"':
			// String / quoted-identifier: backslash escapes the next byte
			// (MySQL), and a doubled quote is an escaped quote.
			q := c
			j := i + 1
			closeIdx := -1
			for j < n {
				if b[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if b[j] == q {
					if j+1 < n && b[j+1] == q {
						j += 2
						continue
					}
					closeIdx = j
					j++
					break
				}
				j++
			}
			end := n // unterminated: blank everything after the opening quote
			if closeIdx >= 0 {
				end = closeIdx // terminated: keep the closing delimiter
			}
			blank(i+1, end)
			i = j
		case c == '`':
			// MySQL backtick identifier: NO backslash escaping inside; a
			// doubled backtick is an escaped backtick. Blanking the content
			// keeps an apostrophe / semicolon / keyword inside an identifier
			// from being mislexed as a string, a statement break, or a verb.
			j := i + 1
			closeIdx := -1
			for j < n {
				if b[j] == '`' {
					if j+1 < n && b[j+1] == '`' {
						j += 2
						continue
					}
					closeIdx = j
					j++
					break
				}
				j++
			}
			end := n
			if closeIdx >= 0 {
				end = closeIdx
			}
			blank(i+1, end)
			i = j
		case c == '[':
			// MSSQL / SQLite bracket-delimited identifier; a doubled ']]' is an
			// escaped ']'. Blanking the content stops a WHERE (or a keyword)
			// inside a bracket identifier from fake-scoping a whole-table write.
			j := i + 1
			closeIdx := -1
			for j < n {
				if b[j] == ']' {
					if j+1 < n && b[j+1] == ']' {
						j += 2
						continue
					}
					closeIdx = j
					j++
					break
				}
				j++
			}
			end := n
			if closeIdx >= 0 {
				end = closeIdx
			}
			blank(i+1, end)
			i = j
		case c == '$':
			if tag, ok := dollarOpen(b, i); ok {
				seq := make([]byte, 0, len(tag)+2)
				seq = append(seq, '$')
				seq = append(seq, tag...)
				seq = append(seq, '$')
				start := i + len(seq)
				j := start
				for j <= n-len(seq) && !bytesEqualAt(b, j, seq) {
					j++
				}
				if j > n-len(seq) {
					j = n // unterminated: rest is body
					blank(start, j)
					i = j
				} else {
					blank(start, j)
					i = j + len(seq)
				}
			} else {
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// dollarOpen reports whether b[i:] begins a Postgres dollar-quote opener
// `$tag$`, returning the tag bytes. The tag is empty or a valid identifier: it
// must NOT start with a digit (Postgres rejects `$1$` as a dollar-quote, and
// `$1`, `$2` are positional parameters, not quotes), which keeps bind
// parameters from being misread as an opening quote.
func dollarOpen(b []byte, i int) (tag []byte, ok bool) {
	if i >= len(b) || b[i] != '$' {
		return nil, false
	}
	isAlpha := func(x byte) bool {
		return x == '_' || (x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z')
	}
	j := i + 1
	// first tag byte, if any, must be alphabetic/underscore (not a digit)
	if j < len(b) && !(b[j] == '$' || isAlpha(b[j])) {
		return nil, false
	}
	for j < len(b) && (isAlpha(b[j]) || (b[j] >= '0' && b[j] <= '9')) {
		j++
	}
	if j < len(b) && b[j] == '$' {
		return b[i+1 : j], true
	}
	return nil, false
}

// sqlForParser returns a copy of stmt safe to hand to the dialect parsers:
// every `$tag$ … $tag$` dollar-quoted body becomes the string literal 'x', and
// every `backtick` identifier becomes a plain identifier. This neutralizes the
// two constructs the linked parsers mishandle, so the parser sees valid SQL and
// its top-level-kind / MutatesViaCTE signals stay reliable. It is NOT length-
// preserving and is used only as parser input; the WHERE/tautology logic uses
// the length-preserving sqlSkeleton instead.
func sqlForParser(stmt string) string {
	b := []byte(stmt)
	n := len(b)
	var out []byte
	i := 0
	for i < n {
		c := b[i]
		switch {
		case c == '\'' || c == '"':
			// Copy a normal string / quoted identifier verbatim (parsers handle
			// these); track escapes so we find the true close.
			q := c
			out = append(out, c)
			j := i + 1
			for j < n {
				if b[j] == '\\' && j+1 < n {
					out = append(out, b[j], b[j+1])
					j += 2
					continue
				}
				if b[j] == q {
					if j+1 < n && b[j+1] == q {
						out = append(out, b[j], b[j+1])
						j += 2
						continue
					}
					out = append(out, b[j])
					j++
					break
				}
				out = append(out, b[j])
				j++
			}
			i = j
		case c == '`':
			// Replace the whole backtick identifier with a plain name.
			j := i + 1
			for j < n {
				if b[j] == '`' {
					if j+1 < n && b[j+1] == '`' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			out = append(out, []byte("id")...)
			i = j
		case c == '$':
			if _, ok := dollarOpen(b, i); ok {
				tag, _ := dollarOpen(b, i)
				seq := append(append([]byte{'$'}, tag...), '$')
				j := i + len(seq)
				for j <= n-len(seq) && !bytesEqualAt(b, j, seq) {
					j++
				}
				if j > n-len(seq) {
					j = n
				} else {
					j += len(seq)
				}
				out = append(out, []byte("'x'")...)
				i = j
			} else {
				out = append(out, c)
				i++
			}
		default:
			out = append(out, c)
			i++
		}
	}
	return string(out)
}

func bytesEqualAt(b []byte, i int, seq []byte) bool {
	if i+len(seq) > len(b) {
		return false
	}
	for k := 0; k < len(seq); k++ {
		if b[i+k] != seq[k] {
			return false
		}
	}
	return true
}

// asciiUpper upper-cases only ASCII a-z, leaving every other byte (including
// multibyte UTF-8 identifier bytes) unchanged, so the result has the SAME byte
// length as the input and offsets computed on it index the original correctly.
func asciiUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// splitSQLStatements splits sql into statements on each `;` that is real code
// (found via the skeleton, so a `;` inside a string / dollar-quote / comment
// does not split), returning the ORIGINAL substrings for the parser.
func splitSQLStatements(sql string) []string {
	sk := sqlSkeleton(sql)
	var out []string
	start := 0
	for i := 0; i < len(sk); i++ {
		if sk[i] == ';' {
			out = append(out, sql[start:i])
			start = i + 1
		}
	}
	if strings.TrimSpace(sql[start:]) != "" {
		out = append(out, sql[start:])
	}
	return out
}

// indexSQLWord returns the byte offset of word (already upper-case) as a whole
// token in upperSQL, or -1. ASCII SQL keywords only, so offsets line up with
// the original mixed-case statement.
func indexSQLWord(upperSQL, word string) int {
	for start := 0; start <= len(upperSQL)-len(word); {
		idx := strings.Index(upperSQL[start:], word)
		if idx < 0 {
			return -1
		}
		pos := start + idx
		var before, after byte = ' ', ' '
		if pos > 0 {
			before = upperSQL[pos-1]
		}
		if pos+len(word) < len(upperSQL) {
			after = upperSQL[pos+len(word)]
		}
		if !isSQLWordByte(before) && !isSQLWordByte(after) {
			return pos
		}
		start = pos + 1
	}
	return -1
}

// cutAtSQLClause truncates s at the first clause keyword that can follow a
// WHERE predicate (so the tautology test sees only the predicate body), and at
// the first ';'.
func cutAtSQLClause(s string) string {
	up := asciiUpper(s)
	cut := len(s)
	for _, kw := range []string{"GROUP", "ORDER", "LIMIT", "HAVING", "RETURNING",
		"WINDOW", "OFFSET", "FETCH", "UNION", "INTERSECT", "EXCEPT"} {
		if idx := indexSQLWord(up, kw); idx >= 0 && idx < cut {
			cut = idx
		}
	}
	if idx := strings.IndexByte(s, ';'); idx >= 0 && idx < cut {
		cut = idx
	}
	return s[:cut]
}

func isSQLWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// hasSQLWord reports whether the SQL contains word (case-insensitive) as a
// whole token, so "WHERE" is not matched inside a column named "elsewhere".
func hasSQLWord(sql, word string) bool {
	return sqlWordSet(sql)[strings.ToUpper(word)]
}

// sqlWordSet splits the SQL into upper-cased alphanumeric/underscore word
// tokens. Deliberately simple and dialect-neutral: it only needs to spot
// leading statement keywords and the WHERE clause, not parse the grammar.
func sqlWordSet(sql string) map[string]bool {
	set := map[string]bool{}
	for _, tok := range strings.FieldsFunc(sql, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')
	}) {
		set[strings.ToUpper(tok)] = true
	}
	return set
}

// ── shell parameter shape ───────────────────────────────────────────────

// shellStringReversibility tokenizes a raw shell command string with the same
// quote-aware lexer used by the protected-path primitive and takes the worst
// class across three surfaces (mirroring shellTouchesProtectedRec):
//
//  1. output redirections — `foo > /dev/sda` overwrites a device even though
//     `foo` reads;
//  2. each per-command segment — so `ls && rm -rf /data` is judged on the rm;
//  3. command substitutions, recursively — `echo $(rm -rf /data)` EXECUTES the
//     inner rm regardless of where the (discarded) output goes.
//
// It starts optimistic (Reversible) and worsens: a single unrecognized program
// worsts to Unknown (which outranks Reversible), so an unfamiliar command is
// escalated, never auto-allowed; a command with no classifiable content at all
// returns Unknown.
func shellStringReversibility(cmd string) ReversibilityClass {
	return shellReversibilityRec(cmd, 0)
}

func shellReversibilityRec(cmd string, depth int) ReversibilityClass {
	toks := tokenizeShell(cmd)
	class := Reversible
	saw := false

	for _, t := range redirectTargets(toks) {
		saw = true
		class = worst(class, redirectReversibility(t))
	}
	for _, seg := range splitShellSegments(toks) {
		words := stripLeadingAssignments(commandWords(seg))
		if len(words) == 0 {
			continue
		}
		saw = true
		class = worst(class, argvReversibility(wordValues(words)))
	}
	if depth < maxShellSubstDepth {
		for _, sub := range extractCommandSubsts(cmd) {
			if strings.TrimSpace(sub) == "" {
				continue
			}
			saw = true
			class = worst(class, shellReversibilityRec(sub, depth+1))
		}
	}
	if !saw {
		return Unknown // nothing classifiable → fail-safe
	}
	return class
}

// redirectReversibility grades an output-redirection target: overwriting a raw
// block device is irreversible, a normal file overwrite/truncate is
// recoverable, the standard discard/terminal sinks are reversible, and an
// unresolved target (built from an expansion we cannot see) fails safe.
func redirectReversibility(t redirTarget) ReversibilityClass {
	if t.unresolved {
		return Unknown
	}
	switch t.value {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero":
		return Reversible
	}
	if strings.HasPrefix(t.value, "/dev/") ||
		strings.HasPrefix(t.value, "/proc/") || strings.HasPrefix(t.value, "/sys/") {
		// raw block device, or a kernel/hardware control surface: a write to
		// /proc/sysrq-trigger forces an immediate kernel action, /proc/sys and
		// /sys reconfigure the running kernel/hardware. Not ordinarily undoable.
		return Irreversible
	}
	return Recoverable
}

// argvReversibility classifies a single already-split command. It peels any
// leading command wrappers (sudo/env/timeout/…) to find the real program, then
// classifies that. Because wrapper option parsing is not perfectly reliable (an
// option that consumes a separate value can make the peel land on the wrong
// token), when a wrapper was present it ALSO scans the whole wrapped region for
// an unambiguous destructive invocation and keeps the worst, so no over-peel
// can auto-allow a catastrophic command sitting past the landed program
// (`env -u ls rm -rf /`).
func argvReversibility(argv []string) ReversibilityClass {
	stripped, hadWrapper := unwrapShellWrappers(argv)
	class := classifyArgv0(stripped)
	if hadWrapper {
		class = worst(class, argvDangerScan(argv))
	}
	return class
}

// classifyArgv0 grades an already-unwrapped command by its program (argv[0]).
// It reuses mutatingProgs / isMutatingProg from the protected-path primitive as
// the base "this writes files" set, then layers the special cases whose
// recoverability differs.
func classifyArgv0(argv []string) ReversibilityClass {
	if len(argv) == 0 {
		return Unknown
	}
	prog := filepath.Base(argv[0])
	args := argv[1:]

	switch {
	case prog == "shred":
		// Secure erase — the whole point is that the data cannot be recovered.
		return Irreversible
	case prog == "rm":
		if hasRecursiveFlag(args) {
			return Irreversible // rm -rf / rm -R: recursive tree deletion
		}
		return Recoverable // a single unlinked file may be restorable
	case prog == "dd":
		if anyHasPrefix(args, "of=") {
			return Irreversible // raw overwrite of a device/file
		}
		return Reversible // dd with no output operand only reads
	case isDiskDestructProg(prog):
		return Irreversible
	case prog == "git":
		if isGitForcePush(args) {
			return Irreversible // rewrites published history
		}
		// Other git subcommands vary too widely to judge from argv alone.
		return Unknown
	case prog == "find":
		// find is a general command executor: `-delete` recursively unlinks
		// every match, `-exec`/`-ok` run an ARBITRARY program (rm -rf, shred),
		// and `-fprint`/`-fprintf`/`-fls` WRITE a file (or a raw device). Only a
		// plain search is reversible.
		if argvTargetsRawDevice(args) || findIsDestructive(args) {
			return Irreversible
		}
		if findWritesFile(args) {
			return Recoverable
		}
		return Reversible
	case prog == "sort":
		// sort is read-only EXCEPT `-o FILE` / `--output=FILE`, which overwrites
		// a file (and `sort -o f f` is the classic in-place clobber).
		if argvTargetsRawDevice(args) {
			return Irreversible
		}
		if anyHasPrefix(args, "-o") || anyHasPrefix(args, "--output") {
			return Recoverable
		}
		return Reversible
	case prog == "uniq":
		// uniq [INPUT [OUTPUT]] — a 2nd positional operand is an OUTPUT file it
		// truncates/overwrites (and it may be a raw device).
		if argvTargetsRawDevice(args) {
			return Irreversible
		}
		if countNonFlagOperands(args) >= 2 {
			return Recoverable
		}
		return Reversible
	}

	if isMutatingProg(prog, argv) {
		// cp / mv / tee / truncate / ln / install / chmod / chown / mkdir /
		// touch / sed -i / dd of= (dd handled above): file mutations that
		// can typically be restored from VCS or a backup — UNLESS the target is
		// a raw block device or kernel control surface (`cp x /dev/sda`,
		// `tee /proc/sysrq-trigger`), which is irreversible.
		if argvTargetsRawDevice(args) {
			return Irreversible
		}
		return Recoverable
	}
	if reversibleShellProgs[prog] {
		return Reversible
	}
	return Unknown
}

// isDiskDestructProg reports whether prog always destroys a disk or volume.
// diskutil/zpool are deliberately excluded: they have read subcommands
// (`diskutil list`, `zpool status`), so the bare program is not destructive.
func isDiskDestructProg(prog string) bool {
	if strings.HasPrefix(prog, "mkfs") || strings.HasPrefix(prog, "newfs") ||
		strings.HasPrefix(prog, "mke2fs") {
		return true
	}
	switch prog {
	case "fdisk", "parted", "sgdisk", "wipefs", "blkdiscard",
		"lvremove", "vgremove", "pvremove":
		return true
	}
	return false
}

// argvDangerScan returns Irreversible if ANY position in argv begins an
// unambiguous destructive invocation (rm -r, shred, a disk-format tool, dd of=,
// git force-push); otherwise Reversible (no contribution). It only raises the
// unmistakable catastrophes and never over-escalates a benign command, so it is
// safe to worst-in for a wrapped command whose option layout could not be
// parsed with certainty.
func argvDangerScan(argv []string) ReversibilityClass {
	for i, a := range argv {
		prog := filepath.Base(a)
		rest := argv[i+1:]
		switch {
		case prog == "shred", isDiskDestructProg(prog):
			return Irreversible
		case prog == "rm" && hasRecursiveFlag(rest):
			return Irreversible
		case prog == "dd" && anyHasPrefix(rest, "of="):
			return Irreversible
		case prog == "git" && isGitForcePush(rest):
			return Irreversible
		case prog == "find" && findIsDestructive(rest):
			return Irreversible
		case (isMutatingProg(prog, argv[i:]) || prog == "sort" || prog == "uniq" ||
			prog == "tee" || prog == "find") && argvTargetsRawDevice(rest):
			return Irreversible // a write-capable command targeting a raw device
		}
	}
	return Reversible
}

// findIsDestructive reports whether a find(1) argv performs deletion or runs an
// arbitrary command: -delete, or any of the exec-family predicates
// (-exec/-execdir/-ok/-okdir) whose argument is a program find will run.
func findIsDestructive(args []string) bool {
	for _, a := range args {
		switch a {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir":
			return true
		}
	}
	return false
}

// findWritesFile reports whether a find(1) argv writes/truncates a file via the
// -fprint / -fprintf / -fls output predicates.
func findWritesFile(args []string) bool {
	for _, a := range args {
		switch a {
		case "-fprint", "-fprint0", "-fprintf", "-fls":
			return true
		}
	}
	return false
}

// argvTargetsRawDevice reports whether any argument names a raw block device or
// a kernel/hardware control surface (a write to which is irreversible),
// EXCLUDING the safe pseudo-devices that are normally sources. Used to escalate
// a write-capable command (cp/mv/tee/sort/uniq/...) that targets such a path
// via a positional operand, where redirectReversibility (which only sees `>`
// targets) would not.
func argvTargetsRawDevice(args []string) bool {
	for _, a := range args {
		if isRawDevicePath(stripOptionPrefix(a)) {
			return true
		}
	}
	return false
}

// stripOptionPrefix removes a leading option wrapper so a device path glued to
// an option is still seen: `--output=/dev/sda` -> `/dev/sda`, `-o/dev/sda` ->
// `/dev/sda`. A bare path is returned unchanged. A relative path that merely
// contains "dev" (e.g. `my/dev/x`) is NOT turned into an absolute /dev/ path.
func stripOptionPrefix(a string) string {
	if strings.HasPrefix(a, "--") {
		if k := strings.IndexByte(a, '='); k >= 0 {
			return a[k+1:]
		}
		return a
	}
	if strings.HasPrefix(a, "-") && len(a) > 1 {
		if k := strings.IndexByte(a, '/'); k >= 0 {
			return a[k:] // -o/dev/sda -> /dev/sda
		}
		return a
	}
	return a
}

func isRawDevicePath(p string) bool {
	switch p {
	case "/dev/null", "/dev/zero", "/dev/stdin", "/dev/stdout", "/dev/stderr",
		"/dev/tty", "/dev/random", "/dev/urandom", "/dev/full":
		return false // safe pseudo-devices (normally sources / discard sinks)
	}
	return strings.HasPrefix(p, "/dev/") ||
		strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/")
}

// countNonFlagOperands counts argv elements that are not option flags.
func countNonFlagOperands(args []string) int {
	c := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			c++
		}
	}
	return c
}

// reversibleShellProgs are common read-only commands. Anything not listed
// here (and not a known mutator) stays Unknown rather than being assumed safe.
var reversibleShellProgs = map[string]bool{
	"ls": true, "cat": true, "grep": true, "egrep": true, "fgrep": true,
	"echo": true, "head": true, "tail": true, "wc": true,
	"pwd": true, "which": true, "stat": true, "file": true, "sort": true,
	"uniq": true, "cut": true, "tr": true, "date": true, "whoami": true,
	"env": true, "printenv": true, "true": true, "false": true, "test": true,
	"df": true, "du": true, "ps": true, "top": true, "uname": true,
}

// shellWrapperProgs run another command given as their trailing arguments.
// Left unstripped, `sudo rm -rf /` or `env rm -rf /` would be classified on
// the wrapper (`sudo`/`env`, benign) and the real destructive command hidden.
var shellWrapperProgs = map[string]bool{
	"env": true, "sudo": true, "doas": true, "nice": true, "ionice": true,
	"nohup": true, "setsid": true, "stdbuf": true, "timeout": true,
	"chroot": true, "command": true, "exec": true, "xargs": true, "time": true,
	"proxychains": true, "proxychains4": true,
}

// wrapperValueOpts lists, per wrapper, the SHORT options that consume the NEXT
// argv element as a separate value (`env -u NAME`, `sudo -u USER`, `timeout -s
// SIG`, `xargs -I REPL`). Without this, the option's value token is mistaken for
// the wrapped program: `env -u ls rm -rf /` would peel to `ls` and auto-allow
// the `rm -rf /`. argvReversibility additionally danger-scans the whole wrapped
// region, so a missed option here still cannot auto-allow a catastrophe.
var wrapperValueOpts = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-U": true, "-p": true, "-C": true, "-h": true, "-r": true, "-t": true, "-T": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"doas":    {"-u": true, "-C": true},
	"timeout": {"-s": true, "-k": true},
	"nice":    {"-n": true},
	"ionice":  {"-c": true, "-n": true, "-p": true},
	"xargs":   {"-I": true, "-i": true, "-n": true, "-P": true, "-s": true, "-L": true, "-l": true, "-d": true, "-E": true, "-e": true, "-a": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
}

// unwrapShellWrappers peels leading command wrappers so the real program is
// classified, returning the remaining argv and whether any wrapper was peeled.
// It skips each wrapper's option flags (consuming a following value for the
// known value-taking options), `NAME=VALUE` assignments (env), and
// numeric/duration operands (timeout 5, nice 10) until the first word that
// looks like the wrapped command. Conservative: if it cannot find the wrapped
// command it returns what remains, which classifies as Unknown (→ escalated),
// never Reversible. Bounded to avoid pathological nesting.
func unwrapShellWrappers(argv []string) ([]string, bool) {
	hadWrapper := false
	for depth := 0; depth < 8 && len(argv) > 0; depth++ {
		prog := filepath.Base(argv[0])
		if !shellWrapperProgs[prog] {
			return argv, hadWrapper
		}
		hadWrapper = true
		valOpts := wrapperValueOpts[prog]
		j := 1
		for j < len(argv) {
			a := argv[j]
			switch {
			case valOpts[a]:
				j += 2 // this option consumes the next token as its value
			case strings.HasPrefix(a, "-"):
				j++ // valueless or self-contained (--opt=val) flag
			case prog == "env" && strings.Contains(a, "="):
				j++ // env VAR=value
			case isDurationOrNumber(a):
				j++ // timeout 5 / nice 10 operand
			default:
				goto done
			}
		}
	done:
		if j > len(argv) {
			j = len(argv)
		}
		argv = argv[j:]
	}
	return argv, hadWrapper
}

// isDurationOrNumber reports whether s is a bare number or a simple duration
// (5, 0.5, 5s, 1m, 2h) — the operand shapes timeout/nice take before the
// command they wrap.
func isDurationOrNumber(s string) bool {
	if s == "" {
		return false
	}
	if n := len(s); n > 1 {
		switch s[n-1] {
		case 's', 'm', 'h', 'd':
			s = s[:n-1]
		}
	}
	dot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' && !dot {
			dot = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// hasRecursiveFlag reports whether any argv element requests recursion, in
// either long (--recursive) or short (-r / -R, possibly bundled as -rf) form.
func hasRecursiveFlag(args []string) bool {
	for _, a := range args {
		if a == "--recursive" {
			return true
		}
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' {
			for _, c := range a[1:] {
				if c == 'r' || c == 'R' {
					return true
				}
			}
		}
	}
	return false
}

// isGitForcePush reports whether the git argv is a force-push (which rewrites
// remote history and cannot be cleanly undone).
func isGitForcePush(args []string) bool {
	push := false
	force := false
	for _, a := range args {
		switch {
		case a == "push":
			push = true
		case a == "-f" || a == "--force" || strings.HasPrefix(a, "--force-with-lease"):
			force = true
		case len(a) > 1 && a[0] == '+' && !strings.Contains(a, "://"):
			// A leading '+' on a refspec forces that ref: `git push origin +main`,
			// `git push origin +HEAD:main`, `git push origin +refs/heads/x`.
			force = true
		}
	}
	return push && force
}

func anyHasPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// ── HTTP parameter shape ────────────────────────────────────────────────

// httpMethodReversibility classifies an outbound HTTP call by its method.
//
//   - GET / HEAD / OPTIONS / TRACE → Reversible  (conventionally read-only)
//   - POST / PUT / PATCH / DELETE  → Unknown (the method proves mutation but
//     cannot prove an endpoint-specific undo path)
//   - anything else                → Unknown
func httpMethodReversibility(method string) ReversibilityClass {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return Reversible
	case "POST", "PUT", "PATCH", "DELETE":
		return Unknown
	default:
		return Unknown
	}
}
