package engine

import (
	"os"
	stdpath "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// The name rule.
//
// The checks in protect.go read a command the way a shell does and look for a
// write in a known position. A shell has more grammar than that reader
// follows, so a command it does not follow could reach a protected path. The
// name rule closes that side without following the grammar: when the text of
// the command names a protected path, the command is denied unless every
// program in it is in readOnlyProgs and the text has none of the constructs
// in shellAnomalyRe. The rule reads the raw text, so it does not depend on
// the tokenizer staying in step with the shell.

// readOnlyProgs are the programs a command may run while its text names a
// protected path. None of them writes a file named in its arguments, and none
// runs another program. tee, awk, find, file, tree, rg and less are left out
// for that reason. sort and uniq are read by readsOnlyWithTheseWords. A write through a redirection is checked
// separately (redirectTargets).
var readOnlyProgs = map[string]bool{
	"cat": true, "ls": true, "head": true, "tail": true, "grep": true,
	"egrep": true, "fgrep": true, "wc": true, "stat": true, "diff": true,
	"cmp": true, "echo": true, "printf": true, "true": true, "false": true,
	"test": true, "[": true, "pwd": true, "jq": true, "sha256sum": true,
	"sha1sum": true, "md5sum": true, "readlink": true, "realpath": true,
	"basename": true, "dirname": true, "cut": true, "tr": true, "nl": true,
	"od": true, "tac": true, "du": true, "df": true,
	"cd": true, "pushd": true, "popd": true,
}

// readsOnlyWithTheseWords reports whether sort or uniq, which are not in
// readOnlyProgs, writes no file and runs no program with these words.
//
// sort writes a file with -o and --output, runs a program with
// --compress-program and makes files in the directory of -T. So no word may
// start with "--", and no word that starts with "-" may hold "o" or "T".
// That also refuses some commands that only read, such as sort --reverse.
//
// uniq writes its second file operand. So at most one word may be an
// operand, and "--" is refused, because the words after it are operands
// whatever they start with.
//
// A word with a part that is not known (a variable) gives false. So does a
// word that holds "{", "*", "?" or "[", in quotes or not: bash can turn a
// brace list or a file name pattern into more words, and one of them can be
// -o or a second operand.
func readsOnlyWithTheseWords(prog string, args []shellToken) bool {
	for _, w := range args {
		if strings.ContainsAny(w.raw, "{*?[") || strings.ContainsAny(w.value, "{*?[") {
			return false
		}
	}
	switch prog {
	case "sort":
		for _, w := range args {
			if w.unresolved || strings.HasPrefix(w.value, "--") {
				return false
			}
			if strings.HasPrefix(w.value, "-") && strings.ContainsAny(w.value, "oT") {
				return false
			}
		}
		return true
	case "uniq":
		operands := 0
		for _, w := range args {
			if w.unresolved || w.value == "--" {
				return false
			}
			if w.value == "-" || !strings.HasPrefix(w.value, "-") {
				operands++
			}
		}
		return operands <= 1
	}
	return false
}

// shellClosers end a compound command and stand alone in their segment.
var shellClosers = map[string]bool{"fi": true, "done": true}

// shellAnomalyRe matches text the tokenizer does not read as bash does: a
// comment, a here-document or here-string, a ${…} expansion, arithmetic
// expansion and a case command. With one of them present the segments the
// tokenizer returns are not trusted.
var shellAnomalyRe = regexp.MustCompile(`(^|[\s;|&(){}])#|<<|\$\{|\$\(\(|(^|[\s;|&(])case\s`)

// homeVarRe matches $HOME and ${HOME} where the name ends.
var homeVarRe = regexp.MustCompile(`\$\{HOME\}|\$HOME\b`)

// extglobRe matches one innermost extended-glob group: @(a|b), ?(a), +(a),
// *(a), !(a).
var extglobRe = regexp.MustCompile(`[@?+*!]\([^()]*\)`)

// maxShellFragments bounds the fragments of one command. A command with more
// is not checked and is denied.
const maxShellFragments = 20000

// maxProtectedBases bounds the directories protectedBases returns.
const maxProtectedBases = 64

// shellFragments returns every piece of the command text that could be a
// path: the text is read without its quotes and backslashes, $HOME becomes
// the home directory, an extended-glob group becomes *, and the result is
// split at blanks and shell operators. Each word is returned with its brace
// expansions, with the value of a glued option (of=, -tDIR,
// --target-directory=), and split at "=", ":", ",", "{" and "}". homeAlts are the
// values the command assigns to HOME. over is true when the command has more
// fragments than maxShellFragments.
func shellFragments(cmd string) (frags, homeAlts []string, over bool) {
	seen := map[string]bool{}
	if runtime.GOOS == "windows" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			homeAlts = append(homeAlts, filepath.ToSlash(home))
		}
	}
	texts := []string{cmd}
	// The same text with its \xHH, \NNN and \uHHHH escapes decoded, as
	// echo -e, printf and $'…' write them.
	if decoded := decodeShellEscapes(cmd); decoded != cmd {
		texts = append(texts, decoded)
	}
	for _, text := range texts {
		var alts []string
		frags, alts, over = appendShellFragments(frags, seen, text)
		if over {
			return nil, nil, true
		}
		homeAlts = append(homeAlts, alts...)
	}
	return frags, homeAlts, false
}

// shellEscapeRe matches one \xHH, \uHHHH, \UHHHHHHHH or octal escape.
var shellEscapeRe = regexp.MustCompile(`\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,4})`)

// decodeShellEscapes replaces each escape shellEscapeRe matches with the
// character it names.
func decodeShellEscapes(s string) string {
	return shellEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
		body, base := m[1:], 8
		if body[0] == 'x' || body[0] == 'u' || body[0] == 'U' {
			body, base = body[1:], 16
		}
		n, err := strconv.ParseInt(body, base, 32)
		if err != nil || n <= 0 {
			return m
		}
		return string(rune(n))
	})
}

// decodeWindowsShellEscapes keeps numeric directory components, such as
// "\001\", as native path text while also reading encoded file names.
// The original POSIX scan still checks the fully decoded interpretation.
func decodeWindowsShellEscapes(s string) string {
	var b strings.Builder
	start := 0
	for _, loc := range shellEscapeRe.FindAllStringIndex(s, -1) {
		if loc[1] < len(s) && (s[loc[1]] == '/' || s[loc[1]] == '\\') {
			continue
		}
		b.WriteString(s[start:loc[0]])
		b.WriteString(decodeShellEscapes(s[loc[0]:loc[1]]))
		start = loc[1]
	}
	b.WriteString(s[start:])
	return b.String()
}

// shellPlainText returns the command text without its quotes and
// backslashes, with $HOME as the home directory and an extended-glob group
// as *.
func shellPlainText(cmd string) string {
	s := cmd
	if home, err := shellHomeDir(); err == nil && home != "" {
		s = homeVarRe.ReplaceAllString(s, strings.ReplaceAll(home, "$", "$$"))
	}
	for i := 0; i < 8 && extglobRe.MatchString(s); i++ {
		s = extglobRe.ReplaceAllString(s, "*")
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
		case '$':
			// $'…' and $"…": the dollar sign is part of the quote.
			if i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"') {
				continue
			}
			b.WriteByte(c)
		case '`':
			b.WriteByte(' ')
		case '\\':
			if i+1 < len(s) {
				i++
				if s[i] != '\n' {
					b.WriteByte(s[i])
				}
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isShellSplit reports whether a character ends a word in the plain text.
func isShellSplit(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || strings.ContainsRune(";|&()<>", r)
}

// otherTildeRe matches a word that bash reads under a directory this check
// does not know: ~+ and ~- (the current and the previous directory, also
// with a number), and ~NAME (the home directory of a user).
var otherTildeRe = regexp.MustCompile(`^~([+-][0-9]*|[A-Za-z0-9._][A-Za-z0-9._-]*)(/|$)`)

// procCwdRe matches a path through the working directory of a process, and
// a path under an open file descriptor (/dev/fd/3/x, /proc/self/fd/3/x). A
// command can change that directory, or open the descriptor on a directory
// (exec 3<DIR), before it uses the path, so the directory is not known here.
var procCwdRe = regexp.MustCompile(`/proc/[^/]+/(task/[^/]+/)?((cwd|root)(/|$)|fd/[^/]+/[^/])|/dev/fd/[^/]+/[^/]`)

// holdsUnknownDir reports whether the word, one of its brace expansions, or
// a file name pattern in it read against the file system, is matched by
// procCwdRe.
func holdsUnknownDir(word string) bool {
	variants := []string{word}
	if strings.ContainsRune(word, '{') {
		if expanded, ok := expandBraces(word); ok {
			variants = append(variants, expanded...)
		}
	}
	for _, v := range variants {
		if procCwdRe.MatchString(v) {
			return true
		}
		if !strings.ContainsAny(v, "*?[") {
			continue
		}
		expansions, over := globLinkExpansions(v)
		if over {
			return true
		}
		for _, e := range expansions {
			if procCwdRe.MatchString(e) {
				return true
			}
		}
	}
	return false
}

// unknownDirWord returns the first word of the command that names a path
// under a directory the check does not know (otherTildeWord), also when the
// word is relative and stands under one of the bases (cd /dev/fd && cat
// 3/f), or "".
func unknownDirWord(cmd string, bases []string) string {
	if w := otherTildeWord(cmd); w != "" {
		return w
	}
	if len(bases) == 0 {
		return ""
	}
	for _, word := range strings.FieldsFunc(shellPlainText(cmd), isShellSplit) {
		if word == "" || strings.ContainsRune("/~-+", rune(word[0])) {
			continue
		}
		for _, base := range bases {
			if base == "~" || strings.HasPrefix(base, "~/") {
				continue
			}
			if holdsUnknownDir(strings.TrimRight(base, "/") + "/" + word) {
				return word
			}
		}
	}
	return ""
}

// assignWordRe matches the start of a word in the form NAME=VALUE. bash
// reads a tilde after the "=" and after each ":" of such a word.
var assignWordRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// otherTildeWord returns the first word of the command that otherTildeRe
// or procCwdRe matches, or "". Such a word counts as the name of a protected path: the
// directory is not known, so it can be a protected one. Quotes are not
// looked at, so a quoted word, which bash leaves as it is, counts too.
func otherTildeWord(cmd string) string {
	for _, word := range strings.FieldsFunc(shellPlainText(cmd), isShellSplit) {
		if holdsUnknownDir(word) {
			return word
		}
		variants := []string{word}
		if strings.ContainsRune(word, '{') {
			if expanded, ok := expandBraces(word); ok {
				variants = append(variants, expanded...)
			}
		}
		for _, v := range variants {
			if otherTildeRe.MatchString(v) {
				return v
			}
			if loc := assignWordRe.FindStringIndex(v); loc != nil {
				for _, part := range strings.Split(v[loc[1]:], ":") {
					if otherTildeRe.MatchString(part) {
						return part
					}
				}
			}
		}
	}
	return ""
}

// networkURLRe matches a word that holds a network address. The text after
// the scheme starts with a host name, so it is not a path on this machine.
// A file:// address is not matched: it names a local path.
var networkURLRe = regexp.MustCompile(`(^|[^A-Za-z0-9+.-])(https?|ftp|ssh|git|wss?)://[^/]`)

func appendShellFragments(frags []string, seen map[string]bool, cmd string) (out, homeAlts []string, over bool) {
	add := func(f string) {
		if f != "" && !seen[f] {
			seen[f] = true
			frags = append(frags, f)
		}
	}
	for _, word := range strings.FieldsFunc(shellPlainText(cmd), isShellSplit) {
		if strings.HasPrefix(word, "HOME=") {
			homeAlts = append(homeAlts, word[len("HOME="):])
		}
		variants := []string{word}
		if strings.ContainsRune(word, '{') {
			if expanded, ok := expandBraces(word); ok {
				variants = append(variants, expanded...)
			}
		}
		for _, v := range variants {
			add(v)
			// A drive colon belongs to the path, including inside an option
			// or ${X:-PATH}. The generic punctuation split below drops it.
			if runtime.GOOS == "windows" {
				for _, part := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune("=,{}", r) }) {
					for i := 0; i+2 < len(part); i++ {
						if isWindowsDriveLetterPath(part[i:]) {
							add(part[i:])
							break
						}
					}
				}
			}
			if stripped := stripPathOption(v); stripped != v {
				add(stripped)
			}
			if strings.ContainsAny(v, "=:,{}") {
				for _, part := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune("=:,{}", r) }) {
					if strings.HasPrefix(part, "//") && networkURLRe.MatchString(v) {
						continue // the host and path of a network address
					}
					add(part)
					// ${X:-PATH} and ${X:+PATH}: the path follows a sign.
					add(strings.TrimLeft(part, "-+?"))
				}
			}
			// A path glued to a short option, as in -o/dir/f and -of.json.
			// A value with no dot and no slash is read as more options
			// (-rf), not as a file name.
			if len(v) > 2 && v[0] == '-' && v[1] != '-' {
				if strings.ContainsAny(v[2:], "./") {
					add(v[2:])
				}
				if i := strings.IndexByte(v, '/'); i > 2 {
					add(v[i:])
				}
			}
			// A path glued to other text, as in x@~/dir: each tail that
			// starts at a tilde.
			for i := 1; i < len(v); i++ {
				if v[i] == '~' {
					add(v[i:])
				}
			}
		}
		if len(frags) > maxShellFragments {
			return nil, nil, true
		}
	}
	return frags, homeAlts, false
}

// fragmentForms returns the paths one fragment may name: the fragment, the
// fragment under each directory in bases when it is relative, and, for a
// tilde form, the fragment under each value the command assigns to HOME.
func fragmentForms(frag string, bases, homeAlts []string) []string {
	if frag == "" {
		return nil
	}
	if frag[0] == '~' {
		if frag != "~" && !strings.HasPrefix(frag, "~/") {
			return nil // ~+, ~-, ~user: otherTildeWord makes the name rule apply
		}
		out := []string{frag}
		for _, alt := range homeAlts {
			if alt != "" {
				out = append(out, strings.TrimRight(alt, "/")+frag[1:])
			}
		}
		return out
	}
	out := []string{frag}
	if frag[0] == '-' || frag[0] == '+' {
		return nil // an option; the value of a glued path option is its own fragment
	}
	if frag[0] != '/' {
		for _, base := range bases {
			out = append(out, fragmentForms(strings.TrimRight(base, "/")+"/"+frag, nil, homeAlts)...)
		}
	}
	return out
}

// namesProtected reports whether a path form is a protected path, is inside a
// protected directory, or is a file name pattern that matches one.
func namesProtected(form string, prefixes []string) (bool, string) {
	if hit, target := matchLiteralPath(form, prefixes); hit {
		return true, target
	}
	return globTouchesProtected(form, false, prefixes)
}

// isAboveProtected reports whether a path form is a directory above a
// protected path, or a pattern that matches one.
func isAboveProtected(form string, prefixes []string) bool {
	if hit, _ := aboveProtected(form, prefixes); hit {
		return true
	}
	hit, _ := globTouchesProtected(form, true, prefixes)
	return hit
}

// isProtectedBase reports whether a relative path in the command is also read
// under the path form. That is so for a directory above a protected path
// (cd ~/.claude) and for a directory that is a protected path or is inside
// one (cd ~/.tool-guard/audit). A form of the second kind counts only when
// the file system has a directory there: a protected file (cat FILE > out)
// is not a place a command can change to.
func isProtectedBase(form string, prefixes []string) bool {
	if hit, _ := aboveProtected(form, prefixes); hit {
		return true
	}
	if !strings.ContainsAny(form, "*?[") {
		if hit, _ := matchLiteralPath(form, prefixes); !hit {
			return false
		}
		for _, cand := range literalPathCandidates(form) {
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				return true
			}
		}
		return false
	}
	if hit, _ := globTouchesProtected(form, true, prefixes); !hit {
		return false
	}
	if hit, _ := globTouchesProtected(form, false, prefixes); !hit {
		return true // the pattern matches only a directory above a path
	}
	// The pattern matches a protected path or something inside one. Go
	// reads "**" and some bracket forms in another way than bash: these
	// count without a look at the file system.
	if strings.Contains(form, "**") || strings.Contains(form, "[") {
		return true
	}
	for _, cand := range literalPathCandidates(form) {
		matches, err := filepath.Glob(cand)
		if err != nil {
			return true
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				return true
			}
		}
	}
	return false
}

// protectedBases returns the directories a relative path in the command is
// also read under. They are the inherited ones, the home directory when the
// command holds a `cd` without an operand, and every fragment that names a
// directory above a protected path, or a directory that is one or is inside
// one (isProtectedBase). The last part does not depend on how the
// directory is used: `cd DIR`, `pushd DIR`, `env -C DIR`, `CDPATH=DIR` and
// `HOME=DIR` all count, and so does a relative fragment under a directory
// found before it (cd ~ && cd .claude). This can add a deny and cannot remove
// one. over is true when there are more than maxProtectedBases.
func protectedBases(toks []shellToken, frags, homeAlts, inherited, prefixes []string) (bases []string, over bool) {
	seen := map[string]bool{}
	add := func(b string) {
		if !seen[b] {
			seen[b] = true
			bases = append(bases, b)
		}
	}
	for _, b := range inherited {
		add(b)
	}
	var cdOperands []string
	for _, seg := range splitShellSegments(toks) {
		words := expandBraceWords(stripCommandPrefix(commandWords(seg)))
		if len(words) == 0 || words[0].unresolved || (words[0].value != "cd" && words[0].value != "pushd") {
			continue
		}
		bare := true
		for _, w := range words[1:] {
			if w.unresolved || w.value == "" || (w.value != "--" && w.value[0] != '-' && w.value[0] != '+') {
				bare = false
			}
			if !w.unresolved && w.value != "" && w.value[0] != '-' && w.value[0] != '+' {
				cdOperands = append(cdOperands, w.value)
			}
		}
		if bare && words[0].value == "cd" {
			add("~")
		}
	}
	// The operand of each cd and pushd, in the order of the text: a
	// relative one is read under the directory of this process and under
	// each directory found before it (cd a && cd b names a/b and b). Without
	// this, `cd sub && echo x > ../../FILE` was read under the directory of
	// this process only.
	for _, op := range cdOperands {
		for _, form := range fragmentForms(op, bases, homeAlts) {
			for _, dir := range cdDirectories(form) {
				// A protected directory, or one inside it, that is not on
				// the file system is not a place a command can change to
				// (isProtectedBase): a command that makes it names it.
				if hit, _ := matchLiteralPath(dir, prefixes); hit && !isProtectedBase(dir, prefixes) {
					continue
				}
				add(dir)
			}
		}
		if len(bases) > maxProtectedBases {
			return nil, true
		}
	}
	// A directory that the command names in another way (git -C DIR,
	// make -C DIR, env -C DIR): it counts when a relative word with ".."
	// names a protected path, or a directory above one, under it.
	for _, dir := range dotDotBases(frags, prefixes) {
		add(dir)
	}
	if len(bases) > maxProtectedBases {
		return nil, true
	}
	for round := 0; round < 4; round++ {
		before := len(bases)
		for _, frag := range frags {
			for _, form := range fragmentForms(frag, bases, homeAlts) {
				if isProtectedBase(form, prefixes) {
					add(form)
				}
			}
			if len(bases) > maxProtectedBases {
				return nil, true
			}
		}
		if len(bases) == before {
			break
		}
	}
	return bases, false
}

// cdDirectories returns the directories a cd operand can name: the operand,
// and for a file name pattern the directories it matches.
func cdDirectories(form string) []string {
	out := []string{form}
	if !strings.ContainsAny(form, "*?[") {
		return out
	}
	for _, cand := range literalPathCandidates(form) {
		matches, err := filepath.Glob(cand)
		if err != nil {
			continue
		}
		for i, m := range matches {
			if i >= 16 {
				break
			}
			out = append(out, filepath.ToSlash(m))
		}
	}
	return out
}

// maxDotDotWords bounds the directories and the relative words dotDotBases
// reads.
const maxDotDotWords = 32

// dotDotBases returns each fragment that is a directory on the file system
// and under which another fragment, a relative path with a ".." part, names
// a protected path, something inside one, or a directory above one.
func dotDotBases(frags, prefixes []string) []string {
	var rels []string
	for _, f := range frags {
		if f == "" || strings.ContainsRune("/~-+", rune(f[0])) || len(rels) >= maxDotDotWords {
			continue
		}
		for _, part := range strings.Split(f, "/") {
			if part == ".." {
				rels = append(rels, f)
				break
			}
		}
	}
	if len(rels) == 0 {
		return nil
	}
	var out []string
	checked := 0
	for _, dir := range frags {
		if dir == "" || dir[0] == '-' || dir[0] == '+' || strings.ContainsAny(dir, "*?[") || len(dir) > maxResolvePathLen {
			continue
		}
		isDir := false
		for _, cand := range literalPathCandidates(dir) {
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				isDir = true
				break
			}
		}
		if !isDir {
			continue
		}
		if checked++; checked > maxDotDotWords {
			break
		}
		for _, rel := range rels {
			if rel == dir {
				continue
			}
			joined := strings.TrimRight(dir, "/") + "/" + rel
			if hit, _ := namesProtected(joined, prefixes); hit || isAboveProtected(joined, prefixes) {
				out = append(out, dir)
				break
			}
		}
	}
	return out
}

// commandNamesProtected returns the first fragment that names a protected
// path, or "". A fragment that is the program name of a command (rm, git)
// is read under the directory of this process only as the exact protected
// path: with that directory inside a protected one, every program name
// would count. The same holds for the program name under a directory in
// work, the directories the tool call says it runs in.
func commandNamesProtected(toks []shellToken, frags, bases, work, homeAlts, prefixes []string) string {
	// The text fragments split whitespace even inside quotes. Keep complete
	// parsed words as well so a quoted path with spaces remains visible.
	for _, tok := range toks {
		if tok.kind == tokWord && !tok.unresolved && strings.ContainsAny(tok.value, " \t") {
			frags = append(frags, tok.value)
		}
	}
	if len(frags) > maxShellFragments {
		return "a command with more words than the check reads"
	}
	progs := map[string]bool{}
	for _, seg := range splitShellSegments(toks) {
		if words := stripCommandPrefix(commandWords(seg)); len(words) > 0 && !words[0].unresolved {
			progs[words[0].value] = true
		}
	}
	for _, frag := range frags {
		var underWork []string
		if progs[frag] && len(work) > 0 {
			underWork = fragmentForms(frag, work, homeAlts)
		}
		for i, form := range fragmentForms(frag, bases, homeAlts) {
			if (i == 0 || containsString(underWork, form)) && progs[frag] && !strings.ContainsAny(frag, "*?[") {
				if equalsProtected(form, prefixes) {
					return shortRaw(frag)
				}
				continue
			}
			if hit, _ := namesProtected(form, prefixes); hit {
				return shortRaw(frag)
			}
		}
	}
	return ""
}

// equalsProtected reports whether the path form is exactly a protected path.
func equalsProtected(form string, prefixes []string) bool {
	for _, cand := range literalPathCandidates(form) {
		for _, prefix := range prefixes {
			fold := ignoresCase(prefix)
			for _, p := range canonicalCandidates(prefix) {
				if cand == p || (fold && strings.EqualFold(cand, p)) {
					return true
				}
			}
		}
	}
	return false
}

// shellOnlyReads reports whether every program the command runs is in
// readOnlyProgs. A shell with a -c command is read through. Anything the
// function does not know is a "no": an unknown program, a program name built
// from an expansion, an assignment or a wrapper before the program name, a
// shell that reads a script or its standard input, and the constructs in
// shellAnomalyRe.
func shellOnlyReads(cmd string, depth int) bool {
	if depth > maxShellSubstDepth {
		return false
	}
	if shellAnomalyRe.MatchString(homeVarRe.ReplaceAllString(cmd, "~")) {
		return false
	}
	// The tokenizer ends a command at a carriage return. bash reads it as a
	// character of the word, so the words after it belong to the same
	// program (uniq a<CR>echo FILE).
	if strings.ContainsRune(cmd, '\r') {
		return false
	}
	toks := tokenizeShell(cmd)
	// A redirection writes with any program. A target under the working
	// directory of a process is a file this check cannot name.
	for _, rt := range redirectTargets(toks) {
		if holdsUnknownDir(rt.value) || holdsUnknownDir(rt.raw) {
			return false
		}
	}
	for _, seg := range splitShellSegments(toks) {
		if !segmentOnlyReads(seg, depth) {
			return false
		}
	}
	for _, sub := range extractCommandSubsts(cmd) {
		if !shellOnlyReads(sub, depth+1) {
			return false
		}
	}
	return true
}

// segmentOnlyReads is the test of shellOnlyReads for one command of the
// text.
func segmentOnlyReads(seg []shellToken, depth int) bool {
	all := commandWords(seg)
	words := stripCommandPrefix(all)
	// Before the program name only a reserved word may stand (if, then,
	// !). An assignment (PATH=/x cat F, LD_PRELOAD=…) or a wrapper
	// (env, sudo) can make the name run another program.
	for _, w := range all[:len(all)-len(words)] {
		if w.raw != w.value || !shellPrefixWords[w.value] {
			return false
		}
	}
	if len(words) == 0 {
		return true
	}
	if words[0].unresolved || words[0].raw != words[0].value {
		return false
	}
	prog := words[0].value
	for _, dir := range []string{"/usr/bin/", "/bin/"} {
		if strings.HasPrefix(prog, dir) && !strings.Contains(prog[len(dir):], "/") {
			prog = prog[len(dir):]
		}
	}
	if shellClosers[prog] && len(words) == 1 {
		return true
	}
	if shellInterpreters[prog] {
		// Only "SHELL -c COMMAND" is read through. Another option can
		// run code (fish --init-command=…, bash --rcfile F, bash -i).
		if len(words) < 3 || words[1].unresolved || words[1].value != "-c" {
			return false
		}
		args := shellDashCArgs(words[1:])
		if len(args) == 0 {
			return false
		}
		for _, arg := range args {
			if !shellOnlyReads(arg.marked, depth+1) {
				return false
			}
		}
		return true
	}
	return readOnlyProgs[prog] || readsOnlyWithTheseWords(prog, words[1:])
}

// unreadWord returns a word of the command that the name rule cannot read
// and that can be a protected path: a word with a brace list of more words
// than maxBraceWords, and the name of the shell option `nocaseglob`. The
// word is expanded here up to maxUnreadBraceWords words, and each word is
// compared with the protected paths part by part. A word that makes more
// words, or that holds $'...' text, is returned without a comparison.
func unreadWord(cmd string, toks []shellToken, bases, prefixes []string) string {
	for _, t := range toks {
		if t.kind != tokWord {
			continue
		}
		if t.value == "nocaseglob" {
			return t.value
		}
		word := homeVarRe.ReplaceAllString(unquoteWord(t.raw), "~")
		if !strings.ContainsRune(word, '{') {
			continue
		}
		if made, ok := expandBraces(homeVarRe.ReplaceAllString(t.raw, "~")); ok && !holdsBraceList(made) {
			continue // the other rules read each word of the list
		}
		if strings.Contains(t.raw, "$'") || strings.Contains(t.raw, "$\"") {
			return word
		}
		open := strings.IndexByte(word, '{')
		head, rest := word[:open], word[open:]
		if eq := strings.LastIndexByte(head, '='); eq >= 0 && strings.HasPrefix(head, "-") {
			head = head[eq+1:] // the value of an option: --file=PATH{...}
		}
		tails, ok := expandLongBraces(rest, maxUnreadBraceWords)
		if !ok {
			return word
		}
		for _, start := range braceHeadForms(head, bases) {
			for _, tail := range tails {
				parts := pathParts(start + tail)
				for _, prefix := range prefixes {
					if partsCanMatch(parts, pathParts(prefix)) {
						return word
					}
				}
			}
		}
	}
	return ""
}

// holdsBraceList reports whether one of the words still holds a brace list
// that bash expands. expandBraces does not expand a list that holds a brace
// group of one word, as in `{json,{b}}`.
func holdsBraceList(words []string) bool {
	for _, w := range words {
		if made, ok := expandLongBraces(unquoteWord(w), 2); !ok || len(made) > 1 {
			return true
		}
	}
	return false
}

// maxUnreadBraceWords bounds the words that unreadWord makes from one word.
const maxUnreadBraceWords = 4096

// Marks that expandLongBraces puts in place of a sequence expression.
const (
	numberSeqMark = "\x00" // {1..100}: a number
	otherSeqMark  = "\x01" // {a..z}: one character from A to z
)

var (
	numberSeqRe = regexp.MustCompile(`^-?[0-9]+\.\.-?[0-9]+(\.\.-?[0-9]+)?$`)
	letterSeqRe = regexp.MustCompile(`^[A-Za-z]\.\.[A-Za-z](\.\.-?[0-9]+)?$`)
)

// unquoteWord removes the quote characters of a word and the backslash
// before a character.
func unquoteWord(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// expandLongBraces expands the brace lists of a word as bash does. A
// sequence expression is not expanded: a mark stands in its place. ok is
// false when the word makes more words than limit.
func expandLongBraces(s string, limit int) (out []string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		end, depth := -1, 0
		for j := i; j < len(s); j++ {
			if s[j] == '{' {
				depth++
			} else if s[j] == '}' {
				if depth--; depth == 0 {
					end = j
					break
				}
			}
		}
		if end < 0 {
			continue // no brace closes this one: it is plain text
		}
		body := s[i+1 : end]
		var parts []string
		depth, last := 0, 0
		for j := 0; j < len(body); j++ {
			switch body[j] {
			case '{':
				depth++
			case '}':
				depth--
			case ',':
				if depth == 0 {
					parts = append(parts, body[last:j])
					last = j + 1
				}
			}
		}
		parts = append(parts, body[last:])
		var mids []string
		switch {
		case len(parts) > 1:
			for _, part := range parts {
				sub, ok := expandLongBraces(part, limit)
				if !ok || len(mids)+len(sub) > limit {
					return nil, false
				}
				mids = append(mids, sub...)
			}
		case numberSeqRe.MatchString(body):
			mids = []string{numberSeqMark}
		case letterSeqRe.MatchString(body):
			mids = []string{otherSeqMark}
		default:
			// Not a list: bash keeps the braces and expands the text in them.
			sub, ok := expandLongBraces(body, limit)
			if !ok {
				return nil, false
			}
			for _, w := range sub {
				mids = append(mids, "{"+w+"}")
			}
		}
		tails, ok := expandLongBraces(s[end+1:], limit)
		if !ok || len(mids)*len(tails) > limit {
			return nil, false
		}
		for _, mid := range mids {
			for _, tail := range tails {
				out = append(out, s[:i]+mid+tail)
			}
		}
		return out, true
	}
	return []string{s}, true
}

// pathParts returns the parts of a path between slashes, after `.` and
// `..` parts are resolved.
func pathParts(p string) []string {
	return strings.FieldsFunc(stdpath.Clean("/"+p), func(r rune) bool { return r == '/' })
}

// partsCanMatch reports whether a word made by expandLongBraces can be the
// protected path, a path under it, or a directory above it. The letter case
// is not compared. A pattern character matches any text in one part.
func partsCanMatch(word, prefix []string) bool {
	for i := 0; i < len(word) && i < len(prefix); i++ {
		if !strings.ContainsAny(word[i], "*?[]"+numberSeqMark+otherSeqMark) {
			if !strings.EqualFold(word[i], prefix[i]) {
				return false
			}
			continue
		}
		var b strings.Builder
		b.WriteString("(?is)^")
		for _, c := range word[i] {
			switch string(c) {
			case "?":
				b.WriteString(`[^/]`)
			case otherSeqMark:
				b.WriteString(`[A-z]`) // the characters from A to z
			case numberSeqMark:
				b.WriteString(`-?[0-9]+`)
			case "*", "[", "]":
				b.WriteString(`[^/]*`)
			default:
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		b.WriteString("$")
		if re, err := regexp.Compile(b.String()); err == nil && !re.MatchString(prefix[i]) {
			return false
		}
	}
	return true
}

// braceHeadForms returns the absolute texts a path can start with when the
// word starts with head: head under the home directory for a tilde form,
// head as it is when absolute, and head under the working directory and
// each base when relative. The text is not cleaned, because it can end in
// the middle of a file name.
func braceHeadForms(head string, bases []string) []string {
	if head == "~" || strings.HasPrefix(head, "~/") {
		home, err := shellHomeDir()
		if err != nil || home == "" {
			return nil
		}
		return []string{filepath.ToSlash(home) + head[1:]}
	}
	if strings.HasPrefix(head, "~") {
		return nil // ~+, ~-, ~NAME: otherTildeWord reads these
	}
	if strings.HasPrefix(head, "/") {
		return []string{head}
	}
	// stdpath.Clean keeps a last part that is the start of a file name.
	under := func(dir string) string {
		joined := stdpath.Clean(strings.TrimRight(dir, "/") + "/" + head)
		if head == "" || strings.HasSuffix(head, "/") {
			joined = strings.TrimRight(joined, "/") + "/"
		}
		return joined
	}
	var out []string
	if wd, err := os.Getwd(); err == nil {
		out = append(out, under(filepath.ToSlash(wd)))
	}
	for _, base := range bases {
		for _, cand := range literalPathCandidates(base) {
			out = append(out, under(cand))
		}
	}
	return out
}
