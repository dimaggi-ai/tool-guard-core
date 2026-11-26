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
var procCwdRe = regexp.MustCompile(`/proc/[^/]+/(task/[^/]+/)?((cwd|root)(/|$)|fd/[^/]+/[^/])|/dev/(fd|stdin|stdout|stderr)/[^/]`)

// collapseSlashDots removes the empty and "." components of a path, which
// the kernel skips: /proc/self//cwd and /proc/self/./cwd are /proc/self/cwd.
// It keeps "..", which must not be read lexically after a symbolic link.
func collapseSlashDots(p string) string {
	if !strings.Contains(p, "//") && !strings.Contains(p, "/.") {
		return p
	}
	parts := strings.Split(p, "/")
	kept := parts[:0:0]
	for i, c := range parts {
		if (c == "" || c == ".") && i > 0 {
			continue
		}
		kept = append(kept, c)
	}
	out := strings.Join(kept, "/")
	if out == "" && strings.HasPrefix(p, "/") {
		out = "/"
	}
	return out
}

// unknownDirRoots are the directories the check reaches only through the
// file system: /proc and /dev/fd, where a link can stand, and /dev/pts, the
// directory above the /dev/fd link.
var unknownDirRoots = []string{"/proc/", "/dev/fd", "/dev/pts/"}

// procPathUnknown reports whether a path goes through a directory the check
// does not know: procCwdRe matches it once empty and "." components are
// removed, or it holds ".." under such a directory. /dev/fd is a link into
// /proc/self and /dev/pts/../fd reaches it, so /dev/pts/../fd/../cwd is
// /proc/self/cwd.
func procPathUnknown(p string) bool {
	c := collapseSlashDots(p)
	if procCwdRe.MatchString(c) {
		return true
	}
	if !strings.Contains(c, "/..") {
		return false
	}
	for _, root := range unknownDirRoots {
		if strings.Contains(c, root) {
			return true
		}
	}
	return false
}

// procDirUnknown reports whether p names one of those directories, or a path
// under it, so what it opens is not known here. The file or directory itself
// is not followed: /dev/stdin, /dev/fd/3 and /proc/self/cwd can each be a
// directory the shell was given (exec 3<DIR, cd /proc/self).
func procDirUnknown(p string) bool {
	c := collapseSlashDots(p)
	for _, d := range []string{"/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"} {
		if c == d || strings.HasPrefix(c, d+"/") {
			return true
		}
	}
	return strings.HasPrefix(c, "/proc/") && !strings.Contains(c, "/fd/")
}

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
		if procPathUnknown(v) {
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
			if procPathUnknown(e) {
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

// segmentShellCommandOnlyReads reports whether a segment the read-only rule
// refused is a call of a shell whose every -c command reads and writes no
// file. The options of the shell are not read: they change what the shell
// does, which is why the caller does not read the whole call through.
func segmentShellCommandOnlyReads(seg []shellToken, depth int) bool {
	words := stripCommandPrefix(commandWords(seg))
	if len(words) == 0 || words[0].unresolved || words[0].raw != words[0].value {
		return false
	}
	prog := words[0].value
	for _, dir := range []string{"/usr/bin/", "/bin/"} {
		if strings.HasPrefix(prog, dir) && !strings.Contains(prog[len(dir):], "/") {
			prog = prog[len(dir):]
		}
	}
	if !shellInterpreters[prog] {
		return false
	}
	for _, w := range words[1:] {
		if w.unresolved {
			return false
		}
		if w.value == "-c" || w.value == "--c" || strings.HasPrefix(w.value, "--command") {
			for _, arg := range shellDashCArgs(words[1:]) {
				if !shellOnlyReads(arg.marked, depth+1) {
					return false
				}
			}
			return true
		}
	}
	return false
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
		// "SHELL -c COMMAND" is read through, because the text of the
		// command is read the same way and a rule that denies it denies the
		// same text when the shell runs it. An option that stands between
		// the program name and the -c is read by the shell itself and
		// changes what runs (bash -c -i CMD starts an interactive shell,
		// bash --rcfile F CMD reads a file), so such a call is not read
		// through: the name rule denies it when its text names a protected
		// path. It is read through only when the -c is the plain option on
		// its own: a cluster that carries it (bash -ce 'cat F') sets an
		// option of the shell too, and the words after the command string
		// are handled below. The command text of a call that is not read
		// through is still read, so a read of a protected file stays
		// allowed and only a write to it is denied (bash -c -x 'cat F').
		if len(words) < 3 || words[1].unresolved || words[1].value != "-c" {
			return false
		}
		if len(words) < 3 || words[1].unresolved || words[1].value != "-c" {
			return false
		}
		args := shellDashCArgs(words[1:])
		if len(args) == 0 {
			return false
		}
		// A word that stands after the command string is a positional
		// parameter, which no program reads, so it changes nothing. A long
		// option there is read by the shell itself, not as a positional
		// (fish -c CMD --init-command CM runs CM2 too), and so is a cluster
		// of short options (bash -c CMD -i starts an interactive shell);
		// both stop the reading. A single "-" is the name of the first
		// positional parameter, a word before the option list (bash -c CMD
		// - NAME) and is left alone.
		for _, w := range words[2+len(args):] {
			if w.unresolved || (len(w.value) > 2 && w.value[0] == '-' && w.value[1] != '+') {
				return false
			}
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
		// The path can start after "=", ":" or "@" (--file=PATH{...},
		// out=PATH{...}, a:PATH{...}, @PATH{...}), after a "/" that stands
		// in front of it (the relative path glued to an option: tar
		// -cf.claude/PATH{...}), and after the dash and the letters of a
		// short option glued to it (tar -cfPATH{...}, python -oPATH{...}: a
		// glued value with no slash at all). Each of these heads is
		// compared.
		heads := []string{head}
		add := func(v string) {
			if v != "" && v != head && !containsString(heads, v) {
				heads = append(heads, v)
			}
		}
		for i := 0; i < len(head); i++ {
			if head[i] == '=' || head[i] == ':' || head[i] == '@' || head[i] == '/' {
				add(head[i+1:])
			}
		}
		if strings.HasPrefix(head, "-") {
			if j := strings.IndexAny(head, "/~"); j > 0 {
				add(head[j:])
			}
			// The option letters of a cluster of at most eight of them, with
			// no dash among them: -cfPATH{...} puts the file after "cf".
			for k := 2; k <= 8 && k < len(head); k++ {
				if !strings.ContainsRune(head[1:k], '-') {
					add(head[k:])
				}
			}
		}
		tails, ok := expandLongBraces(rest, maxUnreadBraceWords)
		if !ok {
			return word
		}
		// The text as the shell reads it, quotes kept, is compared too, so
		// an empty alternative of a brace list, which leaves the rest of the
		// word as text (`> {PATH,{a}}`), is not missed. So is the whole word,
		// read as it stands when the path starts inside the braces
		// (`{/HOME/lnk/..,{1..70}}/P`): there the list, not only the text in
		// front of it, is a head. When the token holds a real expansion such
		// as $HOME, word already holds the "~" form, so adding the raw $HOME
		// text would treat "$HOME" as a literal subdirectory.
		if word != "" && !containsString(heads, word) {
			heads = append(heads, word)
		}
		if !t.unresolved {
			if u := unquoteWord(t.raw); u != "" && !containsString(heads, u) {
				heads = append(heads, u)
			}
		}
		// The EvalSymlinks and Lstat results are kept for the whole word: a
		// list of 4096 words asks the same directories over and over, and one
		// system call per word costs seconds against the time budget of the
		// check.
		cache := map[string]string{}
		lstatCache := map[string]lstatKind{}
		headUnknown := braceHeadUnknown(word)
		if headUnknown && wordHasUnknownExpansion(cmd, t) {
			return word
		}
		for _, h := range heads {
			forms := braceHeadForms(h, bases)
			if headUnknown && holdsDotDot(h) && len(forms) == 0 {
				return word
			}
			for _, start := range forms {
				// The last part before the brace list can be a symbolic link
				// to a directory: a link with no ".." in its name (dlink for
				// .claude) is followed even when no ".." follows it, so the
				// link form of the head is compared as well.
				starts := []string{start}
				if dir := stdpath.Dir(start); dir != "" && dir != "/" && !strings.Contains(dir, "..") {
					if r, ok := evalSymlinkCached(cache, dir); ok {
						if r != dir && strings.HasPrefix(start, dir+"/") {
							starts = append(starts, r+start[len(dir):])
						}
					}
				}
				for _, start := range starts {
					// A start that holds a "/" but begins with an option
					// letter, a ":" or an "@" is not a path the check reads
					// from the working directory: it is the tail of an
					// option (tar -cfDIR/P{...}) or a text the braces left
					// ({DIR/P,{a}}). The "/" inside it is still a directory
					// separator for the kernel, so such a word is not
					// dropped: it fails closed.
					if pathInsideDir(start) {
						return word
					}
					if procPathUnknown(start) || procDirUnknown(start) {
						return word
					}
					if pathInsideDir(start + tails[0]) {
						return word
					}
					// The braces of the whole word decide whether its head
					// has a ".." next to a brace list; see braceHeadUnknown.
					// Fail closed only when a component before a ".." is a
					// symbolic link or cannot be determined safely; plain
					// existing directories and missing paths fall through to
					// the physical-path check below.
					if headUnknown && dotDotHeadOverLink(start, lstatCache) {
						return word
					}
					// Each word of the list is resolved with the disk below,
					// and the EvalSymlinks results of the whole check are
					// kept in cache, so a list of 4096 words asks each
					// directory once.
					for _, tail := range tails {
						// A path through a directory this check does not
						// know (/proc/self/cwd, /dev/fd/3, a ".." under
						// /dev/pts) can name the protected file too, so it
						// is checked before the ".." parts are resolved with
						// the disk.
						if procPathUnknown(start+tail) || procDirUnknown(start+tail) {
							return word
						}
						// A ".." of the tail that a part of the tail
						// removes, or a ".." that stands right after a part
						// the braces made, is not known: the name the list
						// made can be a symbolic link, and the directory the
						// ".." gives back is the physical parent of that
						// link. Such a word fails closed.
						if marksDotDot(tail) || (holdsDotDot(tail) && cancelsDotDot(tail)) {
							return word
						}
						// pathParts removes ".." as text, while the kernel
						// follows the link in front of it first. So the word
						// is walked with the disk whenever its text holds a
						// ".." in the head or in a word of the list: the
						// kernel applies each ".." to the longest existing
						// prefix, after resolving the symbolic links of that
						// prefix, which turns HOME/LNK/../../P into
						// HOME/.claude/P when LNK is a link into
						// HOME/.claude/sub. The whole text of the word is
						// given to the walk, not the head alone, because the
						// ".." that reaches outside can stand in the part of
						// the file name, as the second ".." of the example
						// does. The walk of every word of one list shares
						// cache, so each directory is asked once. A word of
						// an unknown directory, a list part that cancels a
						// ".." as text, or a walk that fails keeps the word
						// unread: the check fails closed.
						p := start + tail
						if holdsDotDot(start) || holdsDotDot(tail) {
							r := physicalPathCached(start+tail, cache)
							if r == "" {
								return word
							}
							p = r
						}
						if procPathUnknown(p) || procDirUnknown(p) {
							return word
						}
						parts := pathParts(p)
						for _, prefix := range prefixes {
							if partsCanMatch(parts, pathParts(prefix)) {
								return word
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// holdsDotDot reports whether p has a ".." part.
func holdsDotDot(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// maxDotDotComponents bounds the number of path components before ".." that
// dotDotHeadOverLink inspects with os.Lstat.
const maxDotDotComponents = 128

// lstatKind records the outcome of one os.Lstat call for a directory prefix
// in front of "..".
type lstatKind uint8

const (
	lstatUnknown  lstatKind = iota
	lstatDir                // plain existing directory
	lstatNotExist           // does not exist on disk
	lstatUnsafe             // symbolic link, non-directory, or other Lstat error
)

// lstatCached memoizes os.Lstat results for one check so a long brace word or
// multiple bases inspect each directory prefix at most once.
func lstatCached(cache map[string]lstatKind, p string) lstatKind {
	if k, ok := cache[p]; ok {
		return k
	}
	fi, err := os.Lstat(p)
	var k lstatKind
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			k = lstatUnsafe
		} else {
			k = lstatDir
		}
	case os.IsNotExist(err):
		k = lstatNotExist
	default:
		k = lstatUnsafe
	}
	cache[p] = k
	return k
}

// wordHasUnknownExpansion reports whether tok contains an unresolved shell
// expansion other than $HOME / ${HOME} (or $HOME when cmd itself assigns
// HOME=).
func wordHasUnknownExpansion(cmd string, tok shellToken) bool {
	if !tok.unresolved {
		return false
	}
	if strings.Contains(cmd, "HOME=") {
		return true
	}
	replaced := homeVarRe.ReplaceAllString(tok.raw, "~")
	if replaced == tok.raw {
		return true
	}
	for _, rt := range tokenizeShell(replaced) {
		if rt.unresolved {
			return true
		}
	}
	return false
}

// braceWordDotDotOverLink reports whether any candidate path head of word
// (including values after "=", ":", "@" or a glued short option) resolves
// under bases to a path with a symbolic link or unsafe component before "..".
func braceWordDotDotOverLink(word string, bases []string, cache map[string]lstatKind) bool {
	head := word
	if open := strings.IndexByte(word, '{'); open >= 0 {
		head = word[:open]
	}
	heads := []string{word}
	add := func(v string) {
		if v != "" && !containsString(heads, v) {
			heads = append(heads, v)
		}
	}
	for i := 0; i < len(head); i++ {
		if head[i] == '=' || head[i] == ':' || head[i] == '@' {
			add(head[i+1:])
		}
	}
	if strings.HasPrefix(head, "-") {
		if j := strings.IndexAny(head, "/~"); j > 0 {
			add(head[j:])
		}
		for k := 2; k <= 8 && k < len(head); k++ {
			if !strings.ContainsRune(head[1:k], '-') {
				add(head[k:])
			}
		}
	}
	for _, h := range heads {
		if !holdsDotDot(h) {
			continue
		}
		forms := braceHeadForms(h, bases)
		if len(forms) == 0 {
			return true
		}
		for _, start := range forms {
			if dotDotHeadOverLink(start, cache) {
				return true
			}
		}
	}
	return false
}

// dotDotHeadOverLink reports whether any path component in front of a ".." in
// p is a symbolic link on disk or cannot be determined safely (an Lstat error
// other than not-exist, a non-directory entry before "..", an unknown variable
// or shell pattern character, a relative path, or more than
// maxDotDotComponents components). Plain existing directories and components
// that do not exist at all return false.
func dotDotHeadOverLink(p string, cache map[string]lstatKind) bool {
	if !holdsDotDot(p) {
		return false
	}
	if len(p) > maxResolvePathLen {
		return true
	}
	var root, rest string
	if strings.HasPrefix(p, "/") {
		root = "/"
		rest = p[1:]
	} else if v := volumeNameOf(p); v != "" && len(v) == 2 && v[1] == ':' {
		if len(p) < 3 || p[2] != '/' {
			return true
		}
		root = v + "/"
		rest = p[3:]
	} else {
		return true
	}
	rawParts := strings.Split(rest, "/")
	lastDotDot := -1
	for i, part := range rawParts {
		if part == ".." {
			lastDotDot = i
		}
	}
	if lastDotDot < 0 {
		return false
	}
	if lastDotDot > maxDotDotComponents {
		return true
	}
	var stack []string
	missingDepth := 0
	for _, part := range rawParts[:lastDotDot] {
		switch part {
		case "", ".":
			continue
		case "..":
			if missingDepth > 0 {
				missingDepth--
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			if strings.ContainsAny(part, "$`*?[{}]"+numberSeqMark+otherSeqMark) {
				return true
			}
			stack = append(stack, part)
			if missingDepth > 0 {
				missingDepth++
				continue
			}
			cur := root + strings.Join(stack, "/")
			switch lstatCached(cache, cur) {
			case lstatDir:
			case lstatNotExist:
				missingDepth = 1
			default:
				return true
			}
		}
	}
	return false
}

// marksDotDot reports whether p has a ".." part that comes after a part with
// a sequence mark, that is, after a part the braces made and no name on the
// disk can be matched with.
func marksDotDot(p string) bool {
	marked := false
	for _, part := range strings.Split(p, "/") {
		if part == ".." && marked {
			return true
		}
		if strings.ContainsAny(part, numberSeqMark+otherSeqMark) {
			marked = true
		}
	}
	return false
}

// cancelsDotDot reports whether the text of a path holds a ".." part that a
// later part removes as text, that is, a ".." with a part after it that is
// not "..". Such a pair is resolved by the file system, not by the text: the
// directory the ".." gives back is the target of the link in front of it, and
// the part after it can be a name the braces made. The check does not follow
// such a path, so it fails closed.
func cancelsDotDot(p string) bool {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if part == ".." && i+1 < len(parts) && parts[i+1] != ".." {
			return true
		}
	}
	return false
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

// braceListHoldsDir reports whether an unquoted brace list inside the head
// has an alternative that holds a "/". Such an alternative names a directory
// in every word the list makes (a file name has no "/"), so a ".." right
// after such a list can be the ".." of that directory, whose physical parent
// the check does not know. A list of plain file names ("free/../free", where
// the list is made by other text) does not show this.
func braceListHoldsDir(head string) bool {
	for i := 0; i < len(head); i++ {
		if head[i] != '{' {
			continue
		}
		end := openBraceEnd(head, i)
		if end < 0 {
			continue
		}
		if alts, list := rawBraceAlts(head[i+1 : end]); list {
			for _, alt := range alts {
				if strings.Contains(alt, "/") {
					return true
				}
			}
		} else if numberSeqRe.MatchString(head[i+1:end]) || letterSeqRe.MatchString(head[i+1:end]) {
			// A sequence expression makes one word of unknown text, so a
			// part it stands in can be any name, a directory among them.
			return true
		}
		i = end
	}
	return false
}

// pathInsideDir reports whether the text of a brace word can name a path
// under a directory this check does not read, because a part the check does
// not treat as a directory stands in front of a "/": an option glued to a
// relative path (tar -cf.claude/P{...}), a separator an option takes
// (a:DIR/P{...}, @DIR/P{...}), or an empty brace alternative that keeps the
// rest of the word as text ({DIR/P,{a}}). Such a word can be the protected
// file under another spelling, so it fails closed.
func pathInsideDir(p string) bool {
	return strings.HasPrefix(p, "-") && strings.Contains(p, "/")
}

// literalBraceAlternatives returns the texts of a redirect target that the
// word reader does not expand: the target as the shell got it and, when its
// braces stand outside quoting, the words its brace lists make. A target
// whose every brace is quoted makes no list in bash, so only the text as it
// stands is returned.
func literalBraceAlternatives(raw string) []string {
	out := []string{raw}
	if strings.ContainsRune(raw, '{') && !allBracesQuoted(raw) {
		for _, w := range []string{unquoteWord(raw), expandRawBraces(raw)} {
			if w != "" && !containsString(out, w) {
				out = append(out, w)
			}
		}
	}
	return out
}

// quoteOrPlain copies one quoted run, one backslash pair or one plain
// character of s from i into b, and returns the index after it.
func quoteOrPlain(b *strings.Builder, s string, i int) int {
	switch c := s[i]; c {
	case '\'', '"':
		for j := i + 1; j < len(s); j++ {
			if s[j] == c {
				b.WriteString(s[i : j+1])
				return j + 1
			}
		}
		b.WriteString(s[i:]) // an unterminated quote: the text as it stands
		return len(s)
	case '\\':
		if i+1 < len(s) {
			b.WriteString(s[i : i+2])
			return i + 2
		}
		b.WriteString(s[i:])
		return len(s)
	default:
		b.WriteByte(c)
		return i + 1
	}
}

// openBraceEnd returns the index of the "}" that closes the "{" at i of s,
// or -1 when none does. Quoted braces and backslashes are not counted.
func openBraceEnd(s string, i int) int {
	depth := 0
	for j := i; j < len(s); {
		switch s[j] {
		case '\'', '"':
			closed := false
			for k := j + 1; k < len(s); k++ {
				if s[k] == s[j] {
					j = k + 1
					closed = true
					break
				}
			}
			if !closed {
				return -1
			}
			continue
		case '\\':
			j += 2
			continue
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return j
			}
		}
		j++
	}
	return -1
}

// expandRawBraces returns the raw text of a word with the brace lists that
// stand outside quoting expanded as bash expands them, keeping the quotes of
// the words it makes. Several words are returned in one text, kept apart by
// a blank. "" means the word makes more words than the check reads, or holds
// a quote that does not close, so the caller fails closed on the word.
func expandRawBraces(raw string) string {
	var b strings.Builder
	i := 0
	for i < len(raw) {
		if raw[i] != '{' {
			i = quoteOrPlain(&b, raw, i)
			continue
		}
		end := openBraceEnd(raw, i)
		if end < 0 {
			return "" // an unterminated quote or a brace that never closes
		}
		body := raw[i+1 : end]
		// A group that is not a list keeps its braces: bash leaves them in
		// the word, and the file the shell makes carries them. A text
		// search cannot tell a list here: it stops its brackets at the first
		// inner brace, so the comma of `{PATH,{a}}`, whose second
		// alternative is a group of one word, is not seen. The body is
		// asked for a comma at its own depth instead, and each alternative
		// is expanded again, so the inner group is expanded as bash expands
		// it.
		mids := []string{raw[i : end+1]}
		if alts, list := rawBraceAlts(body); list {
			if alts == nil {
				return ""
			}
			mids = alts
		}
		tails, ok := expandRawBracesTail(raw[end+1:])
		if !ok || len(mids)*len(tails) > maxBraceWords {
			return ""
		}
		for k, mid := range mids {
			if k > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(mid)
		}
		for _, tail := range tails {
			b.WriteString(tail)
		}
		return b.String()
	}
	return b.String()
}

// expandRawBracesTail returns the raw texts that follow a brace group, one
// per expansion of the lists in it, so the caller can put each tail after the
// alternatives. A text with no unquoted brace list is one text, and a brace
// group that is not a list is kept with its braces.
func expandRawBracesTail(s string) ([]string, bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '{' {
			i = quoteOrPlain(&b, s, i)
			continue
		}
		end := openBraceEnd(s, i)
		if end < 0 {
			return nil, false
		}
		if !holdsCommaAtDepth(s[i+1:end]) && !numberSeqRe.MatchString(s[i+1:end]) && !letterSeqRe.MatchString(s[i+1:end]) {
			b.WriteString(s[i : end+1]) // not a list: the braces stay
			i = end + 1
			continue
		}
		inner, ok := expandRawBracesTail(s[i:])
		if !ok {
			return nil, false
		}
		head := b.String()
		out := make([]string, 0, len(inner))
		for _, w := range inner {
			out = append(out, head+w)
		}
		return out, true
	}
	return []string{b.String()}, true
}

// holdsCommaAtDepth reports whether the body of a brace group holds a comma
// that is not inside a group of its own, the comma that makes bash split the
// group into alternatives. A text search cannot see it: the comma of
// {{a},b} stands inside the braces the search cuts off.
func holdsCommaAtDepth(body string) bool {
	depth := 0
	for i := 0; i < len(body); i++ {
		switch c := body[i]; c {
		case '\'', '"':
			j := i + 1
			for j < len(body) && body[j] != c {
				j++
			}
			i = j
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// rawBraceAlts returns the alternatives of a brace body, each expanded in
// turn, so a group of one word inside a list (`PATH,{a}`) gives the words
// bash makes. list is false when the body holds no comma at its own depth and
// no sequence expression, that is, when bash keeps the braces. nil with list
// true means the body makes more words than the check reads.
func rawBraceAlts(body string) (out []string, list bool) {
	if !holdsCommaAtDepth(body) && !numberSeqRe.MatchString(body) && !letterSeqRe.MatchString(body) {
		return nil, false
	}
	depth, last := 0, 0
	var alts []string
	for j := 0; j < len(body); j++ {
		switch c := body[j]; c {
		case '\'', '"':
			for j++; j < len(body) && body[j] != c; j++ {
			}
		case '\\':
			j++
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				alts = append(alts, body[last:j])
				last = j + 1
			}
		}
	}
	if alts == nil {
		// A sequence expression, or a comma that stands only inside an
		// inner group.
		if numberSeqRe.MatchString(body) {
			return []string{numberSeqMark}, true
		}
		if letterSeqRe.MatchString(body) {
			return []string{otherSeqMark}, true
		}
		return nil, false
	}
	alts = append(alts, body[last:])
	for _, alt := range alts {
		if inner, isList := rawBraceAlts(alt); isList {
			if inner == nil {
				return nil, true
			}
			out = append(out, inner...)
			continue
		}
		out = append(out, alt)
		if len(out) > maxBraceWords {
			return nil, true
		}
	}
	// A sequence expression is one word for bash, not the numbers, so the
	// caller reads it part by part with the mark still in it: the word that
	// {1..70} makes is not known, and every part that does not hold it is
	// compared as text.
	for _, alt := range alts {
		if numberSeqRe.MatchString(alt) || letterSeqRe.MatchString(alt) {
			return []string{alt}, true
		}
	}
	if len(out) > maxBraceWords {
		return nil, true
	}
	return out, true
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
	if head == "" || head[0] == '/' {
		return []string{head}
	}
	// The parts are joined as they stand: stdpath.Clean would remove a
	// ".." as text, while the kernel follows the link in front of it
	// (home/lnk/../P is home/.claude/P when lnk links into .claude), and
	// physicalPath resolves ".." with the disk. Only the empty and "."
	// parts, which the kernel skips, are dropped.
	under := func(dir string) string {
		parts := strings.Split(strings.TrimRight(dir, "/")+"/"+head, "/")
		kept := parts[:0:0]
		for i, c := range parts {
			if (c == "" || c == ".") && i > 0 {
				continue
			}
			kept = append(kept, c)
		}
		joined := strings.Join(kept, "/")
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

// braceHeadUnknown reports whether the head of a brace word can name a path
// the check does not know, that is, whether the word must fail closed
// instead of being resolved. The braces are read from the raw text of the
// word, because the check does not know where the list ends: the head can
// hold a whole list (`{DIR/LNK/..,{1..70}}/P`), the tail of one of its words
// (`lnk/../settings.{json,{1..70}}`), or a plain path that ends before it.
//
// A word whose braces make no list of two or more words names one path as it
// stands, and a word whose braces make a list of one word adds nothing that
// is not known (`{DIR/../DIR,{a}}/P`); both are read. A word that makes no
// list at all — quoted braces, a group of one word, an unclosed group — is
// read as its text.
//
// A list of two or more words is not read when the text of the word holds a
// ".." that a later part removes. The kernel walks a ".." after following
// the link in front of it, so the directory the ".." gives back is the
// physical parent of that link, and the words of the list can be names that
// are symbolic links, so the check does not know what the word names. This
// covers both shapes: the ".." right after a word of the list, and the ".."
// in front of a word of the list, where the name the list made can be the
// link.
//
// A list that makes no such ".." — `DIR/../DIR/{P,Q}`, where no part after
// the ".." is a word of the list — is left to the disk walk, which resolves
// it; only the head is given, so the test must ask the whole word.
func braceHeadUnknown(word string) bool {
	list, ok := braceListCount(word)
	if !ok {
		return true // an unclosed quote or group: the word is not known
	}
	if list < 1 {
		return false // no unquoted list at all: the text names the path
	}
	// Where does the list reach? A group makes a directory when an
	// alternative of it, or the text of the group, holds the "/" of one:
	// `{DIR/P,{a}}` puts the words of the list under a directory, and the
	// word after the group is the tail of such a word, so a ".." among the
	// parts that follow stands after a name the list made and is not known
	// here.
	//
	// A group of file names only (`{json,{1..70}}`) makes no directory: the
	// path ends at that group, and a ".." of the parts in front of it belongs
	// to plain text, which the caller walks with the disk. The one exception
	// is a ".." right in front of such a group: the group can make the name
	// that stands after the "..", and the directory it gives back is the
	// physical parent of the part in front of the "..", which is a symbolic
	// link in `lnk/../settings.{json,{1..70}}`.
	dirs := map[int]bool{}
	for i := 0; i < len(word); i++ {
		if c := word[i]; c == '\'' || c == '"' {
			k := i + 1
			for k < len(word) && word[k] != c {
				k++
			}
			if k == len(word) {
				return true
			}
			i = k
			continue
		}
		if word[i] != '{' {
			continue
		}
		end := openBraceEnd(word, i)
		if end < 0 {
			return true
		}
		body := word[i+1 : end]
		if strings.Contains(body, "/") {
			dirs[i] = true
		} else if alts, isList := rawBraceAlts(body); isList {
			for _, alt := range alts {
				if strings.Contains(alt, "/") {
					dirs[i] = true
					break
				}
			}
		}
		i = end
	}
	// Which ".." of the word are we left to resolve? Two of them cannot be,
	// because the file name that stands after them can be a word of the
	// list, and a word of a list can be the name of a symbolic link whose
	// physical parent the check does not know.
	//
	//   - The ".." of a word of a group that spans it, as the ".." inside
	//     `{DIR/LNK/..,{1..70}}/P`: the part after it is the last alternative
	//     of the group, a name the list made.
	//   - The ".." in front of a part that a group cuts, as the ".." of
	//     `lnk/../settings.{json,{1..70}}`: the name the group made stands
	//     after the ".." and can be the link that stands in front of it.
	//
	// Every other ".." of a brace word belongs to plain text, which the
	// caller walks with the disk: `DIR/../DIR/P{json,{1..70}}` gives back
	// the directory in front of the "..", whatever the list makes after it.
	parts := strings.Split(word, "/")
	for k, part := range parts {
		if part != ".." || k == 0 {
			continue
		}
		if braceCutPart(parts, k) {
			return true
		}
		if braceCutsPartAfter(parts, k) {
			return true
		}
	}
	return false
}

// braceCutsPartAfter reports whether the part right after the ".." at index
// k is cut by an unquoted brace group, that is, whether the list of the word
// makes the name that follows the ".." of the head
// (`lnk/../settings.{json,{1..70}}`). A group further down the word lists
// only file names, which the walk of the caller compares part by part.
func braceCutsPartAfter(parts []string, k int) bool {
	if k+1 >= len(parts) {
		return false
	}
	part := parts[k+1]
	for i := 0; i < len(part); i++ {
		if part[i] == '{' && openBraceEnd(part, i) >= 0 {
			return true
		}
	}
	return false
}

// braceCutPart reports whether a brace group of the word reaches the ".." at
// part index at of the given parts, that is, whether the parts from the ".."
// on stand inside an unquoted group. Such a ".." is a part of a word the list
// made, so the name after it can be a symbolic link and the directory the
// ".." gives back is not known here. A group that stands after the ".."
// (`lnk/../settings.{json,{1..70}}`) does not reach it: the caller walks the
// ".." with the disk and the name the list made is compared part by part.
func braceCutPart(parts []string, at int) bool {
	p := strings.Join(parts, "/")
	// The byte at which the ".." part starts and the byte after it.
	pos := 0
	for i := 0; i < at; i++ {
		pos += len(parts[i]) + 1
	}
	end := pos + len(parts[at])
	for i := 0; i < len(p); i++ {
		if p[i] != '{' {
			continue
		}
		clo := openBraceEnd(p, i)
		if clo < 0 {
			continue
		}
		if i < pos && clo >= end {
			return true // the group spans the ".."
		}
		if i >= end {
			return false // the group stands after the ".."
		}
		i = clo
	}
	return false
}

func braceListCount(word string) (list int, ok bool) {
	for i := 0; i < len(word); i++ {
		if c := word[i]; c == '\'' || c == '"' {
			j := i + 1
			for j < len(word) && word[j] != c {
				j++
			}
			if j == len(word) {
				return 0, false
			}
			i = j
			continue
		}
		switch word[i] {
		case '\\':
			i++
		case '{':
			end := openBraceEnd(word, i)
			if end < 0 {
				return 0, false
			}
			alts, isList := rawBraceAlts(word[i+1 : end])
			if isList {
				if alts == nil {
					return maxBraceWords + 1, true
				}
				return len(alts), true
			}
			i = end
		}
	}
	return 0, true
}
