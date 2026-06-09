package mssql

import (
	"regexp"
	"strings"
)

// hasFourPartName detects [server].[db].[schema].[table] linked-server
// references. T-SQL allows 4-part names like LINKED.master.dbo.sysrolemembers.
// The pattern is 3+ dots inside a bracket-or-identifier span before a
// keyword break.
// fourPartRegex matches both bare-identifier and bracket-identifier
// 4-part names: server.db.schema.table and [server].[db].[schema].[table].
// Bracketed segments allow spaces inside the brackets.
var fourPartRegex = regexp.MustCompile(
	`(?:\b[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])\.(?:\b[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])\.(?:\b[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])\.(?:\b[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])`,
)

func hasFourPartName(s string) bool {
	// Skip common false positives: function-like names typically
	// don't have brackets and don't appear in 4-segment form.
	return fourPartRegex.MatchString(s)
}

// hasModifyingCTE walks the (already comment-and-string-stripped) SQL
// looking for a CTE definition that wraps a DELETE / UPDATE / INSERT /
// MERGE statement. State machine:
//
//	state 0: scanning for "WITH" keyword
//	state 1: inside WITH clause, scanning for "(" that opens CTE body
//	state 2: inside CTE body (depth-1 paren); first significant
//	         keyword decides whether this is a modifying CTE
//
// MS T-SQL semantics: a CTE that writes uses OUTPUT instead of PG's
// RETURNING, but the wrapping shape is identical.
func hasModifyingCTE(s string) bool {
	upper := strings.ToUpper(s)
	tokens := tokenize(upper)
	state := 0
	parenDepth := 0
	cteBodyStart := 0
	for i, tok := range tokens {
		switch state {
		case 0:
			if tok == "WITH" {
				state = 1
			}
		case 1:
			if tok == "(" {
				parenDepth = 1
				cteBodyStart = i + 1
				state = 2
			}
			// Skip over CTE name, optional column list, AS keyword.
			// We don't validate those — we just wait for `(`.
		case 2:
			if tok == "(" {
				parenDepth++
				continue
			}
			if tok == ")" {
				parenDepth--
				if parenDepth == 0 {
					// CTE body closed without finding a modifying
					// keyword. Look ahead for a comma (next CTE) or
					// the outer statement.
					state = 1 // look for another `(` for next CTE
				}
				continue
			}
			// First keyword inside CTE body at depth 1 — this is the
			// statement kind of the CTE.
			if parenDepth == 1 && i == cteBodyStart {
				switch tok {
				case "DELETE", "UPDATE", "INSERT", "MERGE":
					return true
				}
				// Anything else (SELECT, WITH for nested CTE, etc.)
				// — wait until this body closes.
			}
			// Skip body content; the modifying keyword must be the
			// very first one. If we didn't catch it on the first
			// token, the CTE is a SELECT.
			if parenDepth == 1 {
				// Update cteBodyStart so subsequent keywords don't
				// re-trigger the check. Once we've passed it, we're
				// past the chance.
				cteBodyStart = -1
			}
		}
	}
	return false
}

// tokenize splits the input into a flat token list. Recognises:
//
//	identifiers / keywords  → returned uppercase
//	`(` and `)`             → returned as single-char tokens
//	other punctuation       → skipped
//	whitespace              → skipped
//
// String literals were already stripped by stripCommentsAndStrings
// before this is called.
func tokenize(s string) []string {
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

func isIdentStart(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_' || b == '@' || b == '#' || b == '['
}

func isIdentCont(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '_' || b == '@' || b == '#' ||
		b == '.' || b == '[' || b == ']'
}
