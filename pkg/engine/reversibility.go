package engine

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

// ReversibilityClass names whether a tool call's primary effect can be
// undone. It is the signal behind the "irreversibility floor": an action
// that cannot be reversed must never be auto-allowed (see
// policies/irreversibility_floor.yaml).
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
	// window — a file overwrite (recover from VCS/backup), a scoped SQL
	// UPDATE / DELETE ... WHERE, a REST PUT/PATCH/DELETE of one resource.
	Recoverable ReversibilityClass = "recoverable"

	// Irreversible: cannot be undone by any ordinary means — a settled
	// payment/wire/transfer/refund, account or data destruction, a
	// production deploy/publish, physical actuation, DROP/TRUNCATE or an
	// unscoped DELETE, rm -rf. These are the actions the floor gates.
	Irreversible ReversibilityClass = "irreversible"

	// Unknown: the effect could not be classified. FAIL-SAFE — an
	// unrecognized action is treated as caution-worthy, never silently
	// reversible. It is deliberately distinct from Reversible so a policy
	// can require positive proof of reversibility before auto-allowing.
	Unknown ReversibilityClass = "unknown"
)

// reversibilityRank orders the classes so signals derived from different
// parts of a call can be merged by keeping the highest-ranked (most gating)
// one. Irreversible outranks everything, then Recoverable, then a POSITIVE
// Reversible recognition, and finally Unknown at the bottom.
//
// Unknown is the bottom on purpose: it means "no signal recognized this",
// so any positive recognition — even Reversible — should win the merge (a
// "run_sql" tool we don't know by name, carrying a plain SELECT, is
// Reversible, not Unknown). The fail-safe guarantee is kept at the source:
// a call that matches NO signal anywhere stays Unknown here and is never
// downgraded to Reversible (see the classifier's Unknown default).
func reversibilityRank(c ReversibilityClass) int {
	switch c {
	case Irreversible:
		return 3
	case Recoverable:
		return 2
	case Reversible:
		return 1
	case Unknown:
		return 0
	default:
		return 0 // any unexpected value is treated as no-signal
	}
}

// worst returns the higher-ranked (more gating) of two classes.
func worst(a, b ReversibilityClass) ReversibilityClass {
	if reversibilityRank(b) > reversibilityRank(a) {
		return b
	}
	return a
}

// ClassifyReversibility deterministically classifies a tool call by whether
// its effect can be undone. It performs NO network calls and invokes NO LLM
// — the class is derived only from the envelope's tool_name / tool_group and
// the shape of its parameters (SQL statement, shell command, HTTP method).
//
// It combines several independent signals and keeps the WORST (most
// cautious) one, so a single irreversible indicator anywhere in the call is
// never masked by a benign-looking name. When nothing is recognized it
// returns Unknown (fail-safe), never Reversible.
//
// The exact mappings live in clearly-declared tables below so a human can
// audit precisely what is classed how.
func ClassifyReversibility(env domain.ActionEnvelope) ReversibilityClass {
	class := nameGroupReversibility(env.ToolName, env.ToolGroup)

	params := parseParams(env.Parameters)

	// SQL statement (reuses the sqlguard four-dialect classifier, with a
	// keyword fallback when no parser is linked for the deployment). Only
	// parameters.sql is consulted — the same field sql_classify keys off —
	// so a natural-language "query" param on a search tool is never misread
	// as SQL.
	if sql := firstString(params, "sql"); sql != "" {
		class = worst(class, sqlReversibility(sql))
	}

	// Shell command (reuses the quote-aware tokenizer + mutating-program
	// detection already used by the protected-path primitive).
	if isShellTool(strings.ToLower(strings.TrimSpace(env.ToolName))) {
		if cmd := firstString(params, "command", "cmd"); cmd != "" {
			class = worst(class, shellStringReversibility(cmd))
		}
	}
	if argv, ok := normalizeArgv(params["argv"]); ok && len(argv) > 0 {
		class = worst(class, argvReversibility(argv))
	}

	// Outbound HTTP: the method decides reversibility for the egress
	// surface. Presence of parameters.url (the http_classify convention for
	// "this is HTTP") plus parameters.method is the gate.
	if firstString(params, "url") != "" {
		if m := firstString(params, "method"); m != "" {
			class = worst(class, httpMethodReversibility(m))
		}
	}

	return class
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
		if irreversibleAnyToken[t] {
			return Irreversible
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
	cl, ok := classifySQL(sql)
	if !ok {
		return sqlKeywordFallback(sql)
	}
	if len(cl.TopLevelKinds) == 0 {
		return Unknown
	}
	class := Reversible
	// A data-modifying CTE hides a write inside a SELECT
	// (WITH x AS (DELETE ... RETURNING *) SELECT * FROM x); the top-level
	// kind is SELECT but the statement mutates. Treat it as irreversible.
	if cl.MutatesViaCTE {
		class = worst(class, Irreversible)
	}
	for _, k := range cl.TopLevelKinds {
		class = worst(class, sqlKindReversibility(k, sql))
	}
	return class
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
//   - DELETE without a WHERE     → Irreversible (whole-relation wipe)
//   - DELETE ... WHERE           → Recoverable  (scoped; restorable from backup)
//   - UPDATE                     → Recoverable  (prior values recoverable only
//     from a backup / audit trail)
//   - INSERT / CREATE / ALTER /
//     GRANT / REVOKE / SET       → Recoverable  (undoable with effort)
//   - SELECT                     → Reversible   (read-only)
//   - anything else              → Unknown      (fail-safe)
func sqlKindReversibility(k sqlguard.Kind, sql string) ReversibilityClass {
	switch k {
	case sqlguard.KindSelect:
		return Reversible
	case sqlguard.KindDrop, sqlguard.KindTruncate:
		return Irreversible
	case sqlguard.KindDelete:
		if hasSQLWord(sql, "WHERE") {
			return Recoverable
		}
		return Irreversible
	case sqlguard.KindUpdate, sqlguard.KindInsert, sqlguard.KindCreate,
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
	case words["DELETE"]:
		if words["WHERE"] {
			return Recoverable
		}
		return Irreversible
	case words["UPDATE"] || words["INSERT"] || words["ALTER"] ||
		words["CREATE"] || words["GRANT"] || words["REVOKE"]:
		return Recoverable
	case words["SELECT"]:
		return Reversible
	default:
		return Unknown
	}
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
// quote-aware lexer used by the protected-path primitive, splits it into
// per-command segments, and keeps the worst class across them (so
// `ls && rm -rf /data` is judged on the rm, not the ls).
func shellStringReversibility(cmd string) ReversibilityClass {
	class := Unknown
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		words := stripLeadingAssignments(commandWords(seg))
		if len(words) == 0 {
			continue
		}
		class = worst(class, argvReversibility(wordValues(words)))
	}
	return class
}

// argvReversibility classifies a single already-split command (argv[0] is the
// program). It reuses mutatingProgs / isMutatingProg from the protected-path
// primitive as the base "this writes files" set, then layers the special
// cases whose recoverability differs.
func argvReversibility(argv []string) ReversibilityClass {
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
	case strings.HasPrefix(prog, "mkfs"), prog == "fdisk", prog == "parted",
		prog == "sgdisk", prog == "wipefs":
		return Irreversible // reformat / repartition a disk
	case prog == "git":
		if isGitForcePush(args) {
			return Irreversible // rewrites published history
		}
		// Other git subcommands vary too widely to judge from argv alone.
		return Unknown
	}

	if isMutatingProg(prog, argv) {
		// cp / mv / tee / truncate / ln / install / chmod / chown / mkdir /
		// touch / sed -i / dd of= (dd handled above): file mutations that
		// can typically be restored from VCS or a backup.
		return Recoverable
	}
	if reversibleShellProgs[prog] {
		return Reversible
	}
	return Unknown
}

// reversibleShellProgs are common read-only commands. Anything not listed
// here (and not a known mutator) stays Unknown rather than being assumed safe.
var reversibleShellProgs = map[string]bool{
	"ls": true, "cat": true, "grep": true, "egrep": true, "fgrep": true,
	"find": true, "echo": true, "head": true, "tail": true, "wc": true,
	"pwd": true, "which": true, "stat": true, "file": true, "sort": true,
	"uniq": true, "cut": true, "tr": true, "date": true, "whoami": true,
	"env": true, "printenv": true, "true": true, "false": true, "test": true,
	"df": true, "du": true, "ps": true, "top": true, "uname": true,
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
//   - GET / HEAD / OPTIONS / TRACE → Reversible  (safe, read-only)
//   - POST / PUT / PATCH           → Recoverable (creates/overwrites a resource)
//   - DELETE                       → Recoverable (a scoped REST delete is
//     commonly soft/undoable; a truly irreversible destination — delete_account,
//     a payments endpoint — is caught by the tool name/group tables instead,
//     and the worst class wins)
//   - anything else                → Unknown
func httpMethodReversibility(method string) ReversibilityClass {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return Reversible
	case "POST", "PUT", "PATCH", "DELETE":
		return Recoverable
	default:
		return Unknown
	}
}
