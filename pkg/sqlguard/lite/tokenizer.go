package lite

import (
	"regexp"
	"strings"
)

// DialectQuirks tells the tokenizer how to recognise dialect-specific
// string and identifier syntax during the strip phase.
type DialectQuirks struct {
	// DollarQuotes enables Postgres' $tag$...$tag$ string literals.
	DollarQuotes bool
	// BacktickIdentifiers enables MySQL's `id` quoting.
	BacktickIdentifiers bool
	// BracketIdentifiers enables MSSQL's [id] quoting.
	BracketIdentifiers bool
	// DoubleQuoteIdentifiers enables ANSI "id" quoting (PG/SQLite).
	DoubleQuoteIdentifiers bool
}

// UnclosedConstructError is returned by StripCommentsAndStrings when
// a comment, string literal, or dollar-quote opens but never closes
// before EOF. The classifier surfaces this as a parse error so the
// engine fail-closes. Pre-fix bypass class: an unterminated `/*`
// swallowed the entire tail silently, masking smuggled DML from the
// statement-split scan.
type UnclosedConstructError string

func (e UnclosedConstructError) Error() string {
	return "unclosed " + string(e) + " before EOF"
}

// StripCommentsAndStrings replaces comments + string literals +
// quoted-identifiers with whitespace of the same length so position
// info stays intact for first-keyword detection but the structural
// tokens (`;`, `(`, `)`, keywords) remain.
//
// Handles:
//
//	-- line comments
//	/* block comments */  (nested)
//	'...' string literals (doubled '' escape)
//	$tag$...$tag$ dollar-quoted literals (when q.DollarQuotes)
//	`...` identifiers     (when q.BacktickIdentifiers)
//	[...] identifiers     (when q.BracketIdentifiers)
//	"..." identifiers     (when q.DoubleQuoteIdentifiers)
//
// Returns the stripped string and a non-nil UnclosedConstructError
// if any construct opens but never closes. Length is preserved
// byte-for-byte regardless.
func StripCommentsAndStrings(s string, q DialectQuirks) (string, error) {
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
		// /* block comment (nested) */
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
			if depth > 0 {
				return string(out), UnclosedConstructError("block comment")
			}
			continue
		}
		// '...' string
		if c == '\'' {
			out[i] = ' '
			i++
			closed := false
			for i < len(out) {
				if out[i] == '\'' {
					if i+1 < len(out) && out[i+1] == '\'' {
						out[i] = ' '
						out[i+1] = ' '
						i += 2
						continue
					}
					out[i] = ' '
					i++
					closed = true
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			if !closed {
				return string(out), UnclosedConstructError("string literal")
			}
			continue
		}
		// $tag$...$tag$ (Postgres dollar-quoted).
		// Per PG grammar, tag chars are [A-Za-z_][A-Za-z0-9_]* —
		// NO dots, no '@', no '#'. Using the generic isIdentCont
		// (which allows '.') makes the strip accept tags PG would
		// reject as separate tokens, masking smuggled DML.
		if q.DollarQuotes && c == '$' {
			j := i + 1
			for j < len(out) && isDollarTagCont(out[j]) {
				j++
			}
			if j < len(out) && out[j] == '$' {
				tag := string(out[i : j+1]) // e.g. "$body$" or "$$"
				// Erase opener
				for k := i; k <= j; k++ {
					out[k] = ' '
				}
				i = j + 1
				// Scan to closing tag
				closed := false
				for i+len(tag) <= len(out) {
					if string(out[i:i+len(tag)]) == tag {
						for k := i; k < i+len(tag); k++ {
							out[k] = ' '
						}
						i += len(tag)
						closed = true
						break
					}
					if out[i] != '\n' {
						out[i] = ' '
					}
					i++
				}
				if !closed {
					return string(out), UnclosedConstructError("dollar-quoted string " + tag)
				}
				continue
			}
		}
		// `...` identifier (MySQL)
		if q.BacktickIdentifiers && c == '`' {
			out[i] = ' '
			i++
			for i < len(out) && out[i] != '`' {
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
		// [...] identifier (MSSQL)
		if q.BracketIdentifiers && c == '[' {
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
		// "..." ANSI identifier
		if q.DoubleQuoteIdentifiers && c == '"' {
			out[i] = ' '
			i++
			for i < len(out) {
				if out[i] == '"' {
					if i+1 < len(out) && out[i+1] == '"' {
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
		i++
	}
	return string(out), nil
}

// SplitTopLevelStatements splits a stripped SQL string on top-level
// semicolons. Also recognises the T-SQL GO batch separator (its own
// line, case-insensitive) for MSSQL.
func SplitTopLevelStatements(stripped string) []string {
	chunks := goRegex.Split(stripped, -1)
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

// FirstKeyword returns the first identifier-shaped token in s,
// uppercased. Empty string if none.
func FirstKeyword(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	i := 0
	for i < len(s) && (isAlpha(s[i]) || s[i] == '_') {
		i++
	}
	if i == 0 {
		return ""
	}
	return strings.ToUpper(s[:i])
}

// ContainsAnyCI reports whether s contains any of the substrings
// (case-insensitive).
func ContainsAnyCI(s string, needles []string) bool {
	low := strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// CollectFunctions returns the set of function-call-shaped identifiers
// (IDENT followed by `(`) in s, lowercased and de-duped. Filters out
// SQL keywords that legitimately appear before `(` (VALUES, IN, etc).
func CollectFunctions(s string) []string {
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

func isSQLKeyword(s string) bool {
	switch s {
	case "values", "in", "exists", "case", "when", "then", "else", "end",
		"if", "while", "for", "with", "as", "on", "and", "or", "not",
		"select", "from", "where", "group", "by", "having", "order",
		"union", "intersect", "except", "all", "distinct", "any", "some",
		"using", "into", "returning", "limit", "offset":
		return true
	}
	return false
}

// CollectTables walks the tokenizer output for the standard
// table-introducing keywords (FROM, JOIN, INTO, UPDATE, DELETE FROM,
// TABLE) and collects the IDENT (or schema.IDENT) immediately
// following each. CTE names declared in WITH ... AS (...) blocks are
// excluded — they're transient aliases, not real tables.
//
// Returns a de-duplicated list, lower-cased, schema-qualified
// preserved when present. Coverage is the "common subset" of dialect
// table grammar — adequate to catch `TABLE pg_authid`,
// `SELECT * FROM information_schema.tables`, hostile JOINs, etc.
// Misses pathological grammars (multi-target DELETE in some dialects,
// LATERAL JOIN with subquery aliases that don't introduce real tables);
// the policy author's defense-in-depth answer for those is a
// least-privilege DB role.
func CollectTables(stripped string) []string {
	upper := strings.ToUpper(stripped)
	tokens := flatTokenize(upper)
	cteNames := collectCTENames(tokens)
	seen := make(map[string]struct{})
	var out []string

	add := func(t string) {
		if t == "" {
			return
		}
		// Quoted identifiers/built-ins arrive as tokens with the
		// quote chars already stripped by StripCommentsAndStrings —
		// the bare ident is what we want.
		low := strings.ToLower(t)
		// Reserve a few known-non-table SQL words so common false
		// positives don't pollute the list.
		if isTableNoiseToken(low) {
			return
		}
		// CTE names are query-local; treat them as transparent.
		if _, isCTE := cteNames[low]; isCTE {
			return
		}
		if _, dup := seen[low]; dup {
			return
		}
		seen[low] = struct{}{}
		out = append(out, low)
	}

	tableIntroducers := map[string]bool{
		"FROM":  true,
		"JOIN":  true,
		"INTO":  true,
		"UPDATE": true,
		"TABLE":  true, // TABLE x shorthand
	}

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		// DELETE FROM x — handled by FROM matcher.
		// MERGE INTO / INSERT INTO — handled by INTO matcher.
		if !tableIntroducers[tok] {
			continue
		}
		// Skip noise modifiers (LATERAL, ONLY, OUTER, etc.) between
		// keyword and table.
		j := i + 1
		for j < len(tokens) && isJoinModifier(tokens[j]) {
			j++
		}
		if j >= len(tokens) {
			continue
		}
		t := tokens[j]
		// Subquery / values list — skip.
		if t == "(" {
			continue
		}
		// Strip surrounding quoting that survived the strip phase.
		if !isIdentLike(t) {
			continue
		}
		add(t)
	}
	return out
}

// collectCTENames walks the tokens for WITH ... AS (...) CTE names so
// CollectTables can exclude them from the table list.
func collectCTENames(tokens []string) map[string]struct{} {
	out := make(map[string]struct{})
	for i, tok := range tokens {
		if tok != "WITH" {
			continue
		}
		j := i + 1
		if j < len(tokens) && tokens[j] == "RECURSIVE" {
			j++
		}
		for j < len(tokens) {
			if !isIdentLike(tokens[j]) {
				break
			}
			out[strings.ToLower(tokens[j])] = struct{}{}
			j++
			// Skip optional column list.
			if j < len(tokens) && tokens[j] == "(" {
				depth := 1
				j++
				for j < len(tokens) && depth > 0 {
					switch tokens[j] {
					case "(":
						depth++
					case ")":
						depth--
					}
					j++
				}
			}
			if j >= len(tokens) || tokens[j] != "AS" {
				break
			}
			j++
			if j < len(tokens) && tokens[j] == "NOT" {
				j++
			}
			if j < len(tokens) && tokens[j] == "MATERIALIZED" {
				j++
			}
			if j >= len(tokens) || tokens[j] != "(" {
				break
			}
			depth := 1
			j++
			for j < len(tokens) && depth > 0 {
				switch tokens[j] {
				case "(":
					depth++
				case ")":
					depth--
				}
				j++
			}
			if j < len(tokens) && tokens[j] == "," {
				j++
				continue
			}
			break
		}
	}
	return out
}

// isJoinModifier returns true for tokens that may appear between a
// table-introducer keyword and the actual table name.
func isJoinModifier(tok string) bool {
	switch tok {
	case "LATERAL", "ONLY", "OUTER", "INNER", "CROSS", "FULL", "LEFT", "RIGHT", "NATURAL":
		return true
	}
	return false
}

// isTableNoiseToken filters out keyword-like tokens that aren't table
// names. Without this, CollectTables would record words like NULL,
// EXISTS, CASE if they appeared after a `JOIN`/`FROM` keyword in an
// unusual position.
func isTableNoiseToken(tok string) bool {
	switch tok {
	case "select", "with", "values", "case", "when", "exists", "null",
		"true", "false", "where", "having", "group", "order", "limit",
		"by", "as", "on", "using", "set", "default", "return",
		"returning", "fetch", "for", "update", "into":
		return true
	}
	return false
}

// HasModifyingCTE returns true when the stripped SQL contains a CTE
// whose body's first significant keyword is DELETE/UPDATE/INSERT/MERGE.
//
// Implementation: scan every `AS (` position; the first non-trivia
// keyword inside the parens is the CTE's statement kind. This catches
// CTEs at any nesting depth (top-level, inside subqueries, inside
// other CTEs) — more robust than a depth-tracking state machine.
func HasModifyingCTE(stripped string) bool {
	upper := strings.ToUpper(stripped)
	tokens := flatTokenize(upper)
	for i, tok := range tokens {
		if tok != "AS" {
			continue
		}
		// Walk forward looking for the immediate `(`.
		j := i + 1
		for j < len(tokens) {
			if tokens[j] == "(" {
				// Find the first non-trivia keyword inside.
				if k := j + 1; k < len(tokens) {
					kw := tokens[k]
					if kw == "RECURSIVE" && k+1 < len(tokens) {
						kw = tokens[k+1]
					}
					switch kw {
					case "DELETE", "UPDATE", "INSERT", "MERGE":
						return true
					}
				}
				break
			}
			// Optional: column list `AS name(...)` — skip identifier
			// tokens between AS and `(`.
			if isIdentLike(tokens[j]) {
				j++
				continue
			}
			break
		}
	}
	return false
}

func isIdentLike(tok string) bool {
	if tok == "" {
		return false
	}
	c := tok[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '@' || c == '#'
}

// KeywordPastWith returns the first significant keyword AFTER the
// balanced CTE definitions of a WITH clause. Used to distinguish
// "WITH x AS (SELECT 1) SELECT * FROM x" (true SELECT) from
// "WITH x AS (SELECT 1) DELETE FROM users" (DELETE — the CTE is a
// red herring, the real statement is destructive).
//
// Walks the token stream:
//
//  1. skip over the WITH keyword
//  2. optionally skip RECURSIVE
//  3. for each CTE: skip CTE name, optional column list (..), the
//     keyword AS, optional NOT MATERIALIZED / MATERIALIZED, then
//     the balanced ( ... ) body
//  4. if the next token after a body is `,`, repeat for the next CTE
//  5. otherwise the next non-trivia keyword is the post-CTE statement
//
// Returns empty string if the structure doesn't match (caller falls
// back to the original first keyword, which preserves backward
// behaviour).
func KeywordPastWith(stripped string) string {
	upper := strings.ToUpper(stripped)
	tokens := flatTokenize(upper)
	// Find WITH.
	i := 0
	for i < len(tokens) && tokens[i] != "WITH" {
		i++
	}
	if i == len(tokens) {
		return ""
	}
	i++
	if i < len(tokens) && tokens[i] == "RECURSIVE" {
		i++
	}
	// Each iteration consumes one CTE definition.
	for i < len(tokens) {
		// CTE name.
		if !isIdentLike(tokens[i]) {
			return ""
		}
		i++
		// Optional column list.
		if i < len(tokens) && tokens[i] == "(" {
			depth := 1
			i++
			for i < len(tokens) && depth > 0 {
				switch tokens[i] {
				case "(":
					depth++
				case ")":
					depth--
				}
				i++
			}
		}
		// AS keyword.
		if i >= len(tokens) || tokens[i] != "AS" {
			return ""
		}
		i++
		// Optional NOT MATERIALIZED / MATERIALIZED.
		if i < len(tokens) && tokens[i] == "NOT" {
			i++
		}
		if i < len(tokens) && tokens[i] == "MATERIALIZED" {
			i++
		}
		// Body.
		if i >= len(tokens) || tokens[i] != "(" {
			return ""
		}
		depth := 1
		i++
		for i < len(tokens) && depth > 0 {
			switch tokens[i] {
			case "(":
				depth++
			case ")":
				depth--
			}
			i++
		}
		// Comma → another CTE.
		if i < len(tokens) && tokens[i] == "," {
			i++
			continue
		}
		break
	}
	// Skip whitespace tokens are already filtered; return the next
	// identifier-like keyword.
	for i < len(tokens) {
		if isIdentLike(tokens[i]) {
			return tokens[i]
		}
		i++
	}
	return ""
}

func flatTokenize(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		if c == '(' || c == ')' {
			out = append(out, string(c))
			i++
			continue
		}
		if isIdentStart(c) {
			j := i + 1
			for j < len(s) && isIdentCont(s[j]) {
				j++
			}
			out = append(out, s[i:j])
			i = j
			continue
		}
		i++
	}
	return out
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentStart(b byte) bool {
	return isAlpha(b) || b == '_' || b == '@' || b == '#'
}

func isIdentCont(b byte) bool {
	return isAlpha(b) || (b >= '0' && b <= '9') || b == '_' || b == '@' || b == '#' || b == '.'
}

// isDollarTagCont restricts dollar-quote tag characters to the PG
// grammar (no dots / @ / #).
func isDollarTagCont(b byte) bool {
	return isAlpha(b) || (b >= '0' && b <= '9') || b == '_'
}
