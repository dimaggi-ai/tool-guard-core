//go:build sqlite_strict

package sqlite

import (
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

// preClassify is a tiny first-keyword check for SQLite statements that
// rqlite/sql refuses to parse but which we still need to surface so
// policies can route them. Returns (Classification, true) when it
// recognises the input; (zero, false) otherwise → caller falls through
// to the real parser.
//
// Statements handled:
//
//	VACUUM         → KindOther                (maintenance; could be DoS)
//	ATTACH DB '…'  → KindOther + UsesProgram  (file read primitive)
//	DETACH DB …    → KindOther                (DB management)
//	SAVEPOINT n    → KindTransaction          (savepoint create)
//	RELEASE n      → KindTransaction          (savepoint release)
func preClassify(in string) (sqlguard.Classification, bool) {
	first := firstWordUpper(in)
	switch first {
	case "VACUUM":
		return sqlguard.Classification{
			Dialect:       Dialect,
			StmtCount:     1,
			TopLevelKinds: []sqlguard.Kind{sqlguard.KindOther},
		}, true
	case "ATTACH":
		// ATTACH DATABASE 'path' AS name — file read primitive.
		// Treat as a "program/file-touching" statement so policies
		// with no_program_exec deny it.
		return sqlguard.Classification{
			Dialect:       Dialect,
			StmtCount:     1,
			TopLevelKinds: []sqlguard.Kind{sqlguard.KindOther},
			UsesProgram:   true,
		}, true
	case "DETACH":
		return sqlguard.Classification{
			Dialect:       Dialect,
			StmtCount:     1,
			TopLevelKinds: []sqlguard.Kind{sqlguard.KindOther},
		}, true
	case "SAVEPOINT", "RELEASE":
		return sqlguard.Classification{
			Dialect:       Dialect,
			StmtCount:     1,
			TopLevelKinds: []sqlguard.Kind{sqlguard.KindTransaction},
		}, true
	}
	return sqlguard.Classification{}, false
}

// firstWordUpper returns the first whitespace-separated token of s,
// uppercased. Skips a leading "--" or "/*" comment if present at the
// very start.
func firstWordUpper(s string) string {
	s = strings.TrimSpace(s)
	// Skip a single leading comment so "/* ... */ VACUUM" still matches.
	for {
		if strings.HasPrefix(s, "--") {
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = strings.TrimSpace(s[i+1:])
				continue
			}
			return ""
		}
		if strings.HasPrefix(s, "/*") {
			if i := strings.Index(s, "*/"); i >= 0 {
				s = strings.TrimSpace(s[i+2:])
				continue
			}
			return ""
		}
		break
	}
	// Take chars until whitespace.
	end := 0
	for end < len(s) && !isSpace(s[end]) {
		end++
	}
	return strings.ToUpper(s[:end])
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}
