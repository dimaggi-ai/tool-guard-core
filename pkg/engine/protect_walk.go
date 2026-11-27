package engine

import (
	"strings"
	"sync/atomic"
)

// This file holds the helpers that the walk of the net (protect_net.go)
// shares with the reading of a word: the quote marks, the bound on the
// links one walk follows, and the count of file-system lookups.

// quoteMark stands where a quote stood in a word, so a path can start
// after it ("x".claude/P is read as .claude/P as well).
const quoteMark = "\x02"

// maxLinkFollows bounds the symbolic links one walk follows, as the kernel
// does (ELOOP). A walk that needs more fails closed.
const maxLinkFollows = 40

// walkLookups counts the file-system lookups of the net (lstat, readlink,
// readdir). Tests read it to bound the cost of a walk.
var walkLookups atomic.Int64

func joinDir(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// Marks that stand for a brace or a comma that a quote or a backslash made
// plain text, so the brace expansion does not read them.
const (
	plainOpenMark  = "\x04"
	plainCloseMark = "\x05"
	plainCommaMark = "\x06"
)

var plainMarkRestore = strings.NewReplacer(plainOpenMark, "{", plainCloseMark, "}", plainCommaMark, ",")

// markQuotes returns the word with its quotes and backslashes removed, a
// quoteMark where each quote stood, and a plain mark for each brace and
// comma that a quote or a backslash covers. Inside double quotes a
// backslash covers only $, `, ", \ and a newline, as in bash. ok is false
// for a quote that does not close and for a "(" that no quote covers: with
// extglob, @(...) and the like are patterns the check does not expand.
func markQuotes(raw string) (string, bool) {
	var b strings.Builder
	plain := func(c byte) {
		switch c {
		case '{':
			b.WriteString(plainOpenMark)
		case '}':
			b.WriteString(plainCloseMark)
		case ',':
			b.WriteString(plainCommaMark)
		default:
			b.WriteByte(c)
		}
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			if j < 0 {
				return "", false
			}
			b.WriteString(quoteMark)
			for k := i + 1; k < i+1+j; k++ {
				plain(raw[k])
			}
			b.WriteString(quoteMark)
			i += j + 1
		case '"':
			b.WriteString(quoteMark)
			j := i + 1
			for ; j < len(raw) && raw[j] != '"'; j++ {
				if raw[j] == '\\' && j+1 < len(raw) && strings.IndexByte("$`\"\\\n", raw[j+1]) >= 0 {
					j++
				}
				plain(raw[j])
			}
			if j >= len(raw) {
				return "", false
			}
			b.WriteString(quoteMark)
			i = j
		case '\\':
			if i+1 < len(raw) {
				i++
				plain(raw[i])
			}
		case '(':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}
