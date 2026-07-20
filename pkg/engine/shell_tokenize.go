package engine

import "strings"

// This file implements a real, quote-aware POSIX-shell-like tokenizer that
// replaces the previous best-effort byte/whitespace scanner behind
// shellTouchesProtected (see protect.go). It exists because the old scanner
// used strings.Fields (no quote awareness), a one-pair unquote(), and a raw
// byte scan for redirect operators — so quoting, command substitution, and
// variable expansion all slipped through, and a literal separator inside a
// quoted string wrongly split a command in two. Those were documented as
// "accepted limits"; this is the promised replacement that makes shell-write
// coverage real rather than illusory.
//
// GRAMMAR (what tokenizeShell recognizes)
//
//	word          := run of the following, concatenated, with NO unquoted
//	                 whitespace or operator between them:
//	                   - bare characters
//	                   - '…'          single quotes: everything literal, no
//	                                  expansion of any kind (POSIX 2.2.2)
//	                   - "…"          double quotes: literal, EXCEPT \$ \` \" \\
//	                                  \<newline> are the only escapes and
//	                                  $… / `…` still introduce expansions
//	                                  (POSIX 2.2.3). No globbing.
//	                   - \c           backslash escape outside quotes: c is
//	                                  literal; \<newline> is a line continuation
//	                   - $VAR ${…} $(…) `…` $((…))  → expansions (see below)
//	separator     := one of  ;  ;;  &  &&  |  ||  |&  (  )  <newline>  <cr>
//	                 — ends the current command (a "segment").
//	redirection   := >  >>  >|  <>  &>  &>>          (writes a file operand)
//	              |  >&  <&                          (fd-dup: operand is an fd
//	                                                  number, or in bash a file)
//	              |  <  <<  <<-  <<<                 (reads; operand never written)
//	                 An optional leading UNQUOTED fd number (2>, 1>>) binds to
//	                 the operator, not to a word.
//
// Adjacent quoted and unquoted pieces are one word — `'/prot'ected/f`,
// `r”m`, and `"/protected/"f` each resolve to a single concatenated literal.
// This is the property the old one-pair unquote() lacked, and it is what
// closes the concatenated-quoting evasion.
//
// FAIL-CLOSED ON UNRESOLVED EXPANSION (the security-critical decision)
//
// Command substitution ($(…) / `…`) and variable expansion ($VAR / ${…}) are
// deliberately NOT evaluated. This is a deterministic, offline policy control:
// it does not — and must not — execute the substituted command, and it does
// not have the agent's real shell environment, so it cannot know what those
// forms expand to. A tokenizer that guessed (e.g. treated $VAR as the empty
// string, or as its literal text) would manufacture a false answer about a
// path it cannot actually see.
//
// The only correct behavior for a security control that cannot resolve a value
// is to refuse to certify it safe. So every word carries an `unresolved` flag
// set whenever it contained any substitution/expansion we could not evaluate.
//
// Two DISTINCT threats hide behind `unresolved`, and they need different
// handling — conflating them (an earlier version did) is a mistake:
//
//  1. The RESOLVED VALUE is used as a path. `$VAR`/`${VAR}` and the captured
//     OUTPUT of a substitution are side-effect-free as text: they only matter
//     when that text lands in a redirect target or a mutating-command argument.
//     shellTouchesProtected fails closed on an unresolved word in exactly those
//     positions (we can't prove it doesn't resolve under a protected prefix) and
//     nowhere else, so `echo $HOME` does not fire — the fail-closed is scoped to
//     the decisions that actually compare a path.
//  2. The substitution itself EXECUTES a command. `$(…)`/“ `…` “ run their
//     body for its side effects regardless of where the output goes, so
//     `echo $(rm /protected/f)` and `x=$(rm /protected/f)` really delete the
//     file even though the output is never used as a path. Position-scoping is
//     the WRONG test for this: extractCommandSubsts hands each inner command
//     back to shellTouchesProtected, which recurses into it. That is precise —
//     it fires only when the inner command genuinely writes — where a blanket
//     "any substitution anywhere is a hit" would block ubiquitous benign
//     `echo $(date)` / `for f in $(ls)`.
//
// This mirrors the reasoning already documented in path_classify.go
// (DenyOnResolveFailure / the Windows-normalization fix): when the control
// genuinely cannot see the resolved value, it fails toward denial, and the
// choice is documented rather than left implicit.
//
// DOCUMENTED LIMITS (considered, not missed)
//
// The residual limits below fall into two safe classes: OVER-approximations
// (may raise a spurious hit — annoying but never a bypass) and offline-
// unknowable expansions we do NOT fail closed on because doing so would block
// ubiquitous benign commands. For the latter, the robust control is unchanged:
// keep bash OUT of the write-capable policy scope (tg hook/-proxy -protect-paths
// runs regardless of policy).
//
//   - An UNRESOLVED argv[0] (`$CMD /protected/f`) is not classified as
//     mutating: we can't know whether $CMD is `rm`. Failing closed on every
//     command whose program name is a variable would block essentially all
//     dynamic invocations, so — exactly like an unknown binary that isn't in
//     mutatingProgs — such a command is not fired on.
//   - Command WRAPPERS (sudo/env/xargs/nice/timeout/command/exec …) are not
//     unwrapped: `sudo rm /protected/f` is classified on argv[0]=`sudo`, which
//     is not in mutatingProgs, so it is not fired on. Leading variable
//     ASSIGNMENTS (`FOO=bar rm …`) ARE stripped before argv[0] is chosen (a
//     distinct POSIX grammar production), so that specific prefix does not hide
//     the real command; general wrappers are out of scope by design.
//   - TILDE (`~/…`, `~user/…`) and GLOB (`rm /prot*/f`) expansion are not
//     performed: both depend on runtime state we don't have ($HOME, the live
//     filesystem), and failing closed on every `~` or `*` would block extremely
//     common benign commands. They are left literal (so they simply don't match
//     a protected prefix) rather than guessed.
//   - `#` COMMENTS are not stripped; a `>`/verb inside a trailing comment can
//     raise a spurious hit. This is an over-approximation (safe): treating a
//     comment as live can only add a deny, and mis-detecting a comment could
//     drop live text, so we deliberately never treat `#` as a comment.
//   - Here-document BODIES are not parsed specially; a body line that looks like
//     `rm /protected/f` is tokenized as an ordinary command. The old scanner had
//     the same property (it split on the newline) — an over-approximation, never
//     a bypass.
//   - Arithmetic `$((…))` is flagged `unresolved` like any other `$(`-form. It
//     cannot yield a path, so the only effect is a possible conservative hit if
//     such a word is a mutating-command argument — the safe direction.
type shellTokenKind int

const (
	tokWord       shellTokenKind = iota // a shell word (command name, argument, or redirect operand)
	tokSep                              // a control operator that ends a command: ; ;; & && | || |& ( ) newline
	tokRedirWrite                       // output redirection whose operand is a file we may WRITE: > >> >| <> &> &>>
	tokRedirDup                         // fd-dup redirection >& <& : operand is an fd number (2>&1) or, in bash, a file
	tokRedirRead                        // input redirection < << <<- <<< : operand is read, never written
)

// shellToken is one lexical token. For a tokWord, `value` is the word with
// quotes/escapes resolved and unresolved expansions elided, `raw` is the exact
// source substring (kept for human-readable audit reasons), and `unresolved`
// records that the word contained substitution/expansion we could not evaluate.
// For operator tokens, `value` is the operator text and the other fields are
// unused.
type shellToken struct {
	kind       shellTokenKind
	value      string
	raw        string
	unresolved bool
}

// tokenizeShell lexes a raw shell command string into a flat token stream.
// It performs a single left-to-right pass with no lookahead beyond the current
// operator, and never executes or resolves anything — expansions are detected
// and skipped, not evaluated (see the file header for why). Malformed input
// (an unterminated quote or substitution) is consumed to end-of-string rather
// than rejected: this is a detector, so degrading to "one long literal word"
// is safe (it can only over-match), whereas erroring out would let a
// deliberately-malformed command dodge the check entirely.
func tokenizeShell(cmd string) []shellToken {
	var toks []shellToken

	var wb strings.Builder // resolved literal of the in-progress word
	wordStart := -1        // source index where the in-progress word began
	unresolved := false    // in-progress word contained an unresolved expansion
	started := false       // a word has begun (may still be empty, e.g. "")

	begin := func(pos int) {
		if !started {
			wordStart = pos
			started = true
		}
	}
	flush := func(end int) {
		if started {
			toks = append(toks, shellToken{
				kind:       tokWord,
				value:      wb.String(),
				raw:        cmd[wordStart:end],
				unresolved: unresolved,
			})
		}
		wb.Reset()
		wordStart = -1
		unresolved = false
		started = false
	}

	i := 0
	n := len(cmd)
	for i < n {
		c := cmd[i]

		// Unquoted whitespace ends a word but is not itself a token.
		if c == ' ' || c == '\t' {
			flush(i)
			i++
			continue
		}

		// Control / redirection operators. Recognized before quotes because
		// outside a quote these characters are always operators, never word
		// content.
		if kind, text, opLen := matchShellOperator(cmd, i); opLen > 0 {
			// An unquoted, unexpanded, all-digits word immediately preceding a
			// redirection is a file-descriptor number (2>, 1>>) that binds to
			// the operator, not a standalone argument. `raw == value` proves no
			// quoting/escaping/expansion happened.
			if isRedirKind(kind) && started && wb.Len() > 0 &&
				cmd[wordStart:i] == wb.String() && isAllDigits(wb.String()) {
				wb.Reset()
				wordStart = -1
				unresolved = false
				started = false
			} else {
				flush(i)
			}
			toks = append(toks, shellToken{kind: kind, value: text})
			i += opLen
			continue
		}

		switch c {
		case '\'':
			// Single quotes: everything literal until the next single quote.
			begin(i)
			i++
			for i < n && cmd[i] != '\'' {
				wb.WriteByte(cmd[i])
				i++
			}
			if i < n {
				i++ // consume closing quote
			}
			continue

		case '"':
			// Double quotes: literal except the POSIX escapes \$ \` \" \\
			// \<newline>, and $…/`…` still introduce (unresolved) expansions.
			begin(i)
			i++
			for i < n && cmd[i] != '"' {
				switch {
				case cmd[i] == '\\' && i+1 < n && isDquoteEscape(cmd[i+1]):
					if cmd[i+1] != '\n' { // \<newline> is a line continuation: drop both
						wb.WriteByte(cmd[i+1])
					}
					i += 2
				case cmd[i] == '$':
					newi, isExp, lit := consumeDollar(cmd, i)
					if lit {
						wb.WriteByte('$')
					} else if isExp {
						unresolved = true
					}
					i = newi
				case cmd[i] == '`':
					unresolved = true
					i = skipBacktick(cmd, i)
				default:
					wb.WriteByte(cmd[i])
					i++
				}
			}
			if i < n {
				i++ // consume closing quote
			}
			continue

		case '`':
			// Backtick command substitution outside quotes: unresolved.
			begin(i)
			unresolved = true
			i = skipBacktick(cmd, i)
			continue

		case '$':
			begin(i)
			// bash ANSI-C ($'…') and locale ($"…") quoting are NOT decoded:
			// mark the word unresolved and skip the quoted region raw. Without
			// this, a hex/octal-encoded path — rm $'\x2fprotected\x2ff' — would
			// tokenize to a harmless literal and slip past. This form only
			// exists OUTSIDE double quotes (inside "…" the following quote is
			// either literal or the closing delimiter), which is why it lives
			// here in the unquoted branch and not in consumeDollar.
			if i+1 < n && cmd[i+1] == '\'' {
				unresolved = true
				i = skipDollarSingleQuote(cmd, i+1)
				continue
			}
			if i+1 < n && cmd[i+1] == '"' {
				unresolved = true
				i = skipDoubleQuoteRaw(cmd, i+1)
				continue
			}
			newi, isExp, lit := consumeDollar(cmd, i)
			if lit {
				wb.WriteByte('$')
			} else if isExp {
				unresolved = true
			}
			i = newi
			continue

		case '\\':
			// Backslash escape outside quotes: next character is literal;
			// backslash-newline is a line continuation (both dropped).
			begin(i)
			if i+1 < n {
				if cmd[i+1] == '\n' {
					i += 2
					continue
				}
				wb.WriteByte(cmd[i+1])
				i += 2
				continue
			}
			i++ // trailing backslash: drop
			continue

		default:
			begin(i)
			wb.WriteByte(c)
			i++
		}
	}
	flush(n)
	return toks
}

// matchShellOperator reports the operator token starting at s[i], or opLen==0
// when s[i] does not begin an operator. It uses longest-match so multi-byte
// operators (&&, >>, <<-, <<<, &>>) win over their prefixes. Only the operator
// shapes that matter for segmentation and redirect-target extraction are
// distinguished; anything else that starts with one of these characters (there
// is nothing else in POSIX) is covered by the single-character fallbacks.
func matchShellOperator(s string, i int) (kind shellTokenKind, text string, opLen int) {
	c := s[i]
	next := func(off int) byte {
		if i+off < len(s) {
			return s[i+off]
		}
		return 0
	}
	switch c {
	case '\n', '\r':
		return tokSep, string(c), 1
	case ';':
		if next(1) == ';' {
			return tokSep, ";;", 2
		}
		return tokSep, ";", 1
	case '&':
		if next(1) == '&' {
			return tokSep, "&&", 2
		}
		if next(1) == '>' {
			if next(2) == '>' {
				return tokRedirWrite, "&>>", 3
			}
			return tokRedirWrite, "&>", 2
		}
		return tokSep, "&", 1
	case '|':
		if next(1) == '|' {
			return tokSep, "||", 2
		}
		if next(1) == '&' {
			return tokSep, "|&", 2
		}
		return tokSep, "|", 1
	case '(':
		return tokSep, "(", 1
	case ')':
		return tokSep, ")", 1
	case '>':
		switch next(1) {
		case '>':
			return tokRedirWrite, ">>", 2
		case '|':
			return tokRedirWrite, ">|", 2
		case '&':
			return tokRedirDup, ">&", 2
		}
		return tokRedirWrite, ">", 1
	case '<':
		switch next(1) {
		case '<':
			if next(2) == '<' {
				return tokRedirRead, "<<<", 3
			}
			if next(2) == '-' {
				return tokRedirRead, "<<-", 3
			}
			return tokRedirRead, "<<", 2
		case '&':
			return tokRedirDup, "<&", 2
		case '>':
			return tokRedirWrite, "<>", 2
		}
		return tokRedirRead, "<", 1
	}
	return tokWord, "", 0
}

// consumeDollar handles a '$' at s[i] (in a context where expansions apply,
// i.e. anywhere except inside single quotes). It advances past the expansion
// and reports whether an actual expansion was present (isExpansion) or the '$'
// is a literal dollar (literalDollar) that the caller should emit verbatim.
// It does not evaluate anything — see the file header for the rationale.
func consumeDollar(s string, i int) (next int, isExpansion bool, literalDollar bool) {
	if i+1 >= len(s) {
		return i + 1, false, true // lone trailing '$'
	}
	switch c := s[i+1]; {
	case c == '(':
		return skipCommandSubst(s, i+1), true, false // $(…) and $((…))
	case c == '{':
		return skipParamExpansion(s, i+1), true, false // ${…}
	case isNameStart(c):
		j := i + 2
		for j < len(s) && isNameChar(s[j]) {
			j++
		}
		return j, true, false // $VAR
	case isSpecialParam(c):
		return i + 2, true, false // $@ $* $# $? $! $- $$ $0..$9
	default:
		return i + 1, false, true // '$' before a non-expansion char → literal
	}
}

// skipCommandSubst skips a $(…) command substitution (also $((…)) arithmetic)
// starting at the opening '(' at s[i]. It counts parentheses but honors nested
// quotes and backticks so a ')' that lives inside a quoted string — e.g.
// $(echo ")") — does not close the substitution early. Returns the index just
// past the matching ')', or len(s) if unterminated.
func skipCommandSubst(s string, i int) int {
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '\'':
			i = skipSingleQuoteRaw(s, i)
			continue
		case '"':
			i = skipDoubleQuoteRaw(s, i)
			continue
		case '`':
			i = skipBacktick(s, i)
			continue
		case '\\':
			i += 2
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return i
}

// skipParamExpansion skips a ${…} parameter expansion starting at the opening
// '{' at s[i]. Like skipCommandSubst it counts braces while honoring nested
// quotes (a '}' inside a quoted default value does not close early). Returns
// the index just past the matching '}', or len(s) if unterminated.
func skipParamExpansion(s string, i int) int {
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '\'':
			i = skipSingleQuoteRaw(s, i)
			continue
		case '"':
			i = skipDoubleQuoteRaw(s, i)
			continue
		case '`':
			i = skipBacktick(s, i)
			continue
		case '\\':
			i += 2
			continue
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return i
}

// skipSingleQuoteRaw returns the index just past the single-quoted region that
// begins at s[i]=='\”. No escapes exist inside single quotes.
func skipSingleQuoteRaw(s string, i int) int {
	i++
	for i < len(s) && s[i] != '\'' {
		i++
	}
	if i < len(s) {
		i++
	}
	return i
}

// skipDollarSingleQuote returns the index just past a bash ANSI-C $'…' region
// whose opening quote is at s[i]=='\”. Unlike a POSIX single-quoted string,
// ANSI-C quoting honors backslash escapes, so `\'` is an escaped quote that does
// NOT terminate the region — `$'\”` is the one-character string "'". Using the
// POSIX skipSingleQuoteRaw here (which treats `\` as literal and stops at the
// first `'`) ended the region one quote early and let the tokenizer re-open a
// stray single-quote that swallowed a following real redirect; this
// escape-aware skip fixes that. We still evaluate nothing — the word stays
// unresolved — we only need to consume the correct span.
func skipDollarSingleQuote(s string, i int) int {
	i++
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '\'' {
			return i + 1
		}
		i++
	}
	return i
}

// skipDoubleQuoteRaw returns the index just past the double-quoted region that
// begins at s[i]=='"'. Backslash escapes the next byte so an escaped '"' does
// not close the region.
func skipDoubleQuoteRaw(s string, i int) int {
	i++
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '"' {
			return i + 1
		}
		i++
	}
	return i
}

// skipBacktick returns the index just past the backtick-substitution region
// that begins at s[i]=='`'. Backslash escapes the next byte.
func skipBacktick(s string, i int) int {
	i++
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '`' {
			return i + 1
		}
		i++
	}
	return i
}

// isDquoteEscape reports whether, inside double quotes, a backslash before c is
// an escape. POSIX 2.2.3: only $ ` " \ and <newline> are escapable; before any
// other character the backslash is literal.
func isDquoteEscape(c byte) bool {
	switch c {
	case '$', '`', '"', '\\', '\n':
		return true
	}
	return false
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// isSpecialParam reports whether c is a POSIX special parameter that forms a
// one-character expansion after '$' ($@ $* $# $? $! $- $$ and $0..$9).
func isSpecialParam(c byte) bool {
	switch c {
	case '@', '*', '#', '?', '!', '-', '$':
		return true
	}
	return c >= '0' && c <= '9'
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isBareFd reports whether a redirect-dup operand is a plain file descriptor
// (a number, or '-' meaning "close") rather than a filename. `2>&1` and `>&-`
// dup/close descriptors and write no file; `>&out.log` (bash) names a file.
func isBareFd(s string) bool {
	return s == "-" || isAllDigits(s)
}

func isRedirKind(k shellTokenKind) bool {
	return k == tokRedirWrite || k == tokRedirDup || k == tokRedirRead
}

// extractCommandSubsts returns the inner command text of every top-level
// command substitution — $(…) and `…` — that would actually EXECUTE when cmd
// runs. This is the one place where "unresolved" is not enough: unlike variable
// expansion, a command substitution RUNS a command for its side effects
// regardless of where its captured output lands, so `echo $(rm /protected/f)`
// and `x=$(rm /protected/f)` really delete the file even though the output is
// never used as a path. The caller (shellTouchesProtected) recurses into each
// returned body so the inner write is caught precisely — and ONLY when the inner
// command truly writes, so benign `echo $(date)` / `x=$(cat f)` do not fire.
//
// Substitutions inside SINGLE quotes are literal (not executed) and skipped;
// inside double quotes they ARE active and collected. Arithmetic $((…)) runs no
// command and is skipped. ${…} parameter expansion is skipped (its rarely-used
// funsub/`${ …;}` form is out of scope, noted in the file header's limits).
// Nested substitutions are reached by the caller's recursion on each body.
func extractCommandSubsts(cmd string) []string {
	var out []string
	i, n := 0, len(cmd)
	inDQuote := false
	for i < n {
		c := cmd[i]
		switch {
		case c == '\\':
			i += 2 // escaped byte (over-skipping a literal '\' is harmless here)
		case !inDQuote && c == '\'':
			i = skipSingleQuoteRaw(cmd, i)
		case c == '"':
			inDQuote = !inDQuote
			i++
		case c == '`':
			end := skipBacktick(cmd, i)
			if end-1 > i+1 {
				out = append(out, cmd[i+1:end-1])
			}
			i = end
		case c == '$' && i+1 < n && cmd[i+1] == '(' && !(i+2 < n && cmd[i+2] == '('):
			end := skipCommandSubst(cmd, i+1) // index past the matching ')'
			if end-1 > i+2 {
				out = append(out, cmd[i+2:end-1])
			}
			i = end
		case c == '$' && i+1 < n && cmd[i+1] == '(': // $(( … )) arithmetic: no command
			i = skipCommandSubst(cmd, i+1)
		case c == '$' && i+1 < n && cmd[i+1] == '{':
			i = skipParamExpansion(cmd, i+1)
		default:
			i++
		}
	}
	return out
}
