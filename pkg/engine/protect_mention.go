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

// maxProtectedBases bounds the directories protectedBases returns, and the
// directories at or above a protected path one command may name (netCheck).
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
//
// A descriptor itself (/dev/fd/3, /proc/self/fd/0, /dev/stdin) is matched as
// well: the command can open it on the protected file (exec 3<FILE). The
// standard output and error (/dev/stdout, /dev/stderr, /dev/fd/1, /dev/fd/2)
// are not; otherTildeWord and knownStream read those.
var procCwdRe = regexp.MustCompile(`/proc/[^/]+/(task/[^/]+/)?((cwd|root)(/|$)|fd/[^/]+/[^/]|fd/(0|[3-9]|[1-9][0-9]+)$)|/dev/fd/[^/]+/[^/]|/dev/(stdin|stdout|stderr)/[^/]|/dev/fd/(0|[3-9]|[1-9][0-9]+)$|/dev/stdin$`)

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
// file system: /proc, where a link can stand, and /dev, which holds the
// /dev/fd link. A ".." under any directory of /dev (/dev/pts/.., /dev/shm/..)
// can reach /dev/fd.
var unknownDirRoots = []string{"/proc/", "/dev/"}

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
	return procLinkRe.MatchString(c)
}

// procLinkRe matches a link of /proc to a file or directory of a process:
// its working directory, its root, its program, and its open descriptors.
// Other files of /proc (/proc/sys/vm/drop_caches, /proc/self/oom_score_adj)
// are plain files of the kernel.
var procLinkRe = regexp.MustCompile(`^/proc/[^/]+/(task/[^/]+/)?(cwd|root|exe|fd|fd/[^/]+|map_files|map_files/[^/]+)$`)

// streamTargetRe matches the standard output and error of the shell under
// their device names.
var streamTargetRe = regexp.MustCompile(`^/dev/(stdout|stderr|fd/[12])$|^/proc/(self|thread-self)/fd/[12]$`)

// knownStream reports whether a redirection target is the standard output
// or error of the shell, in a command that puts no other file on those
// descriptors. Such a target writes to what the shell was given. Only a
// redirection that reads into a descriptor other than 0 (1<FILE, 2<>FILE,
// 1<&N, 7<FILE for the fd/7 form) can put another file there before the
// target is opened again, and a command with one is not treated so. A plain
// `<FILE`, `<<WORD`, `<>FILE` or `<&N` reads into descriptor 0.
func knownStream(p string, toks []shellToken) bool {
	if !streamTargetRe.MatchString(collapseSlashDots(p)) {
		return false
	}
	for i, t := range toks {
		switch t.kind {
		case tokRedirRead:
			if t.fd != "" && strings.TrimLeft(t.fd, "0") != "" {
				return false
			}
		case tokRedirWrite, tokRedirDup:
			if strings.ContainsRune(t.value, '<') && t.fd != "" && strings.TrimLeft(t.fd, "0") != "" {
				return false
			}
			// A copy of another descriptor (>&0, 2>&3, 1<&4) can put a
			// file opened for input on the standard output or error.
			if t.kind == tokRedirDup && i+1 < len(toks) && toks[i+1].kind == tokWord {
				if op := toks[i+1].value; isAllDigits(op) && op != "1" && op != "2" {
					return false
				}
			}
		}
	}
	return true
}

// unknownTarget reports whether a redirection target goes through a
// directory or file the check does not know (procPathUnknown,
// procDirUnknown). The standard output and error of the shell are known
// (knownStream).
func unknownTarget(p string, toks []shellToken) bool {
	if knownStream(p, toks) {
		return false
	}
	return procPathUnknown(p) || procDirUnknown(p) || linkIntoProc(p)
}

// maxLinkWalkParts bounds the parts of one path linkIntoProc walks. A path
// with more fails closed.
const maxLinkWalkParts = 512

// linkIntoProc reports whether a symbolic link on the way of a path leads
// into /proc or /dev (home/pl -> /proc/self/cwd), where the file the kernel
// opens belongs to a process and not to a text the check can follow. A
// relative path is read under the directory of this process. Only links
// are looked at: a path that does not reach one returns false.
func linkIntoProc(p string) bool {
	if p == "" || len(p) > maxResolvePathLen {
		return false
	}
	if !strings.HasPrefix(p, "/") {
		if strings.HasPrefix(p, "~") || filepath.IsAbs(p) || volumeNameOf(p) != "" {
			return false
		}
		wd, err := os.Getwd()
		if err != nil {
			return false
		}
		p = strings.TrimRight(filepath.ToSlash(wd), "/") + "/" + p
		if len(p) > maxResolvePathLen {
			return false
		}
	}
	cur := ""
	for i, part := range strings.Split(p[1:], "/") {
		if i > maxLinkWalkParts {
			return true // a path with more parts than the check walks
		}
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			cur = stdpath.Dir("/" + strings.TrimPrefix(cur, "/"))
			if cur == "/" {
				cur = ""
			}
			continue
		}
		next := cur + "/" + part
		fi, err := os.Lstat(next)
		if err != nil {
			return false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if strings.HasPrefix(next, "/proc/") || strings.HasPrefix(next, "/dev/") {
				return false // the magic links themselves are read by procPathUnknown
			}
			target, err := os.Readlink(next)
			if err != nil {
				return true
			}
			target = filepath.ToSlash(target)
			if !strings.HasPrefix(target, "/") {
				target = cur + "/" + target
			}
			c := collapseSlashDots(stdpath.Clean(target))
			if c == "/proc" || c == "/dev" || strings.HasPrefix(c, "/proc/") || strings.HasPrefix(c, "/dev/") {
				return true
			}
			r, err := filepath.EvalSymlinks(next)
			if err != nil {
				return false
			}
			cur = filepath.ToSlash(r)
			if strings.HasPrefix(cur, "/proc/") || strings.HasPrefix(cur, "/dev/") {
				return true
			}
			continue
		}
		cur = next
	}
	return false
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
		if procPathUnknown(v) || linkIntoProc(v) {
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
			// The letters of a cluster stand before the value, so the value
			// can start after any of them (tar -cvvvfPATH).
			if len(v) > 2 && v[0] == '-' && v[1] != '-' {
				for k := 2; k < len(v) && k <= 32 && v[k-1] != '/'; k++ {
					if strings.ContainsAny(v[k:], "./") {
						add(v[k:])
					}
				}
				if i := strings.IndexByte(v, '/'); i > 2 {
					add(v[i:])
				}
			}
			// A path glued after a character that is not part of a path:
			// a+PATH, a@PATH, a%PATH.
			tails := 0
			for i := 0; i < len(v)-1 && tails < 32; i++ {
				if strings.IndexByte("@+%", v[i]) >= 0 {
					add(v[i+1:])
					tails++
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
// one. It holds at most maxProtectedBases directories; the net reads the
// directories of a command that names more (netCheck).
func protectedBases(toks []shellToken, frags, homeAlts, inherited, prefixes []string) (bases []string) {
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
		if len(bases) >= maxProtectedBases {
			return bases
		}
	}
	for round := 0; round < 4; round++ {
		before := len(bases)
		for _, frag := range frags {
			for _, form := range fragmentForms(frag, bases, homeAlts) {
				// A pattern is read by the net, which matches it against
				// the directories that are there (netCheck).
				if strings.ContainsAny(form, "*?[") {
					continue
				}
				if isProtectedBase(form, prefixes) {
					add(form)
				}
			}
			if len(bases) >= maxProtectedBases {
				return bases
			}
		}
		if len(bases) == before {
			break
		}
	}
	return bases
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
	// A path can start where a quote stood ("x".claude/P): the text after
	// each quote of a word is read as well, with its brace lists.
	for _, tok := range toks {
		if tok.kind != tokWord || tok.unresolved || tok.raw == tok.value || !strings.ContainsAny(tok.raw, "'\"") || len(tok.raw) > maxResolvePathLen {
			continue
		}
		marked, ok := markQuotes(tok.raw)
		if !ok {
			continue
		}
		marked = plainMarkRestore.Replace(marked)
		n := 0
		for i := 0; i < len(marked) && n < 32; i++ {
			if marked[i] != quoteMark[0] {
				continue
			}
			n++
			tail := strings.ReplaceAll(marked[i+1:], quoteMark, "")
			if tail == "" {
				continue
			}
			frags = append(frags, tail)
			if strings.ContainsRune(tail, '{') {
				if made, ok := expandBraces(tail); ok {
					frags = append(frags, made...)
				}
			}
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
		// "SHELL -c COMMAND" is read through, because the text of the
		// command is read the same way and a rule that denies it denies the
		// same text when the shell runs it. The options of the shell are
		// read by parseShellCall. The call is read through only when every
		// option only changes how the shell runs its commands (-e, -x,
		// --norc): an option that reads a startup file or the standard
		// input (-i, -l, -s, --rcfile), sets a named option (-o NAME) or
		// writes a file (fish -o FILE) makes the call not read only, and
		// the name rule denies it when its text names a protected path. A
		// word after the text of -c is a positional parameter, which no
		// program reads (bash -c 'cat F' --arg). Every text the shell runs
		// must read only, the value of fish -C as well.
		call := parseShellCall(prog, words[1:])
		if !call.known || !call.dashC || !call.plain || call.stdin || len(call.commands) == 0 {
			return false
		}
		for _, arg := range call.commands {
			if !shellOnlyReads(arg.marked, depth+1) {
				return false
			}
		}
		return true
	}
	return readOnlyProgs[prog] || readsOnlyWithTheseWords(prog, words[1:])
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
	work := 0
	return expandLongBracesW(s, limit, &work)
}

// maxBraceWork bounds the characters the brace expanders of the old rules
// read for one word, over every level of their recursion. Over it they
// return ok false, and the word is not read.
const maxBraceWork = 1 << 18

func expandLongBracesW(s string, limit int, work *int) (out []string, ok bool) {
	// match[i] is the "}" that closes the "{" at i, or -1: a "{" that no
	// "}" closes is plain text. The pairs are found once for the whole
	// word: the body of a pair, a part of a body between its commas and
	// the text after a pair hold the same pairs on their own, so each
	// level of the recursion reads its range of the one table.
	match := make([]int32, len(s))
	var open []int32
	for j := 0; j < len(s); j++ {
		match[j] = -1
		switch s[j] {
		case '{':
			open = append(open, int32(j))
		case '}':
			if n := len(open); n > 0 {
				match[open[n-1]] = int32(j)
				open = open[:n-1]
			}
		}
	}
	return expandLongBracesRange(s, match, 0, len(s), limit, work)
}

// expandLongBracesRange is expandLongBracesW for the text s[lo:hi].
func expandLongBracesRange(s string, match []int32, lo, hi, limit int, work *int) (out []string, ok bool) {
	if *work += hi - lo + 1; *work > maxBraceWork {
		return nil, false
	}
	for i := lo; i < hi; i++ {
		if s[i] != '{' {
			continue
		}
		end := int(match[i])
		if end < 0 || end >= hi {
			continue
		}
		body := s[i+1 : end]
		type span struct{ lo, hi int }
		var parts []span
		depth, last := 0, i+1
		for j := i + 1; j < end; j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
			case ',':
				if depth == 0 {
					parts = append(parts, span{last, j})
					last = j + 1
				}
			}
		}
		parts = append(parts, span{last, end})
		var mids []string
		switch {
		case len(parts) > 1:
			for _, part := range parts {
				sub, ok := expandLongBracesRange(s, match, part.lo, part.hi, limit, work)
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
			sub, ok := expandLongBracesRange(s, match, i+1, end, limit, work)
			if !ok {
				return nil, false
			}
			for _, w := range sub {
				mids = append(mids, "{"+w+"}")
			}
		}
		tails, ok := expandLongBracesRange(s, match, end+1, hi, limit, work)
		if !ok || len(mids)*len(tails) > limit {
			return nil, false
		}
		for _, mid := range mids {
			for _, tail := range tails {
				out = append(out, s[lo:i]+mid+tail)
			}
		}
		return out, true
	}
	return []string{s[lo:hi]}, true
}

// literalBraceAlternatives returns the texts of a redirect target that the
// word reader does not expand: the target as the shell got it and, when its
// braces stand outside quoting, the words its brace lists make. A target
// whose every brace is quoted makes no list in bash, so only the text as it
// stands is returned.
func literalBraceAlternatives(raw string) []string {
	out := []string{raw}
	if strings.ContainsRune(raw, '{') && !allBracesQuoted(raw) {
		words := []string{unquoteWord(raw)}
		if made, ok := expandQuotedBraces(raw, maxBraceWords); ok {
			words = append(words, made...)
		}
		for _, w := range words {
			if w != "" && !containsString(out, w) {
				out = append(out, w)
			}
		}
	}
	return out
}

// quotedChar is one character of a word, with whether quoting made it plain
// text. bash expands only a brace, a comma and a ".." that no quote covers.
type quotedChar struct {
	c      byte
	quoted bool
}

// quotedChars returns the characters of the raw text of a word with the
// quotes and backslashes removed, each marked as quoted or not. ok is false
// for a quote that does not close.
func quotedChars(raw string) (out []quotedChar, ok bool) {
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			if j < 0 {
				return nil, false
			}
			for k := i + 1; k < i+1+j; k++ {
				out = append(out, quotedChar{raw[k], true})
			}
			i += j + 1
		case '"':
			j := i + 1
			for ; j < len(raw) && raw[j] != '"'; j++ {
				if raw[j] == '\\' && j+1 < len(raw) && strings.IndexByte("$`\"\\\n", raw[j+1]) >= 0 {
					j++
				}
				out = append(out, quotedChar{raw[j], true})
			}
			if j >= len(raw) {
				return nil, false
			}
			i = j
		case '\\':
			if i+1 < len(raw) {
				i++
				out = append(out, quotedChar{raw[i], true})
			}
		default:
			out = append(out, quotedChar{c, false})
		}
	}
	return out, true
}

// expandQuotedBraces returns the words bash makes from the brace lists of
// the raw text of a word, with the quotes removed. A brace, a comma or a
// sequence inside quotes is plain text, and a group with no list keeps its
// braces, as in bash. ok is false for a quote that does not close, for a
// sequence the check does not expand, and for more words than limit.
func expandQuotedBraces(raw string, limit int) ([]string, bool) {
	chars, ok := quotedChars(raw)
	if !ok {
		return nil, false
	}
	return expandQuotedChars(chars, limit)
}

// expandQuotedChars expands the brace lists of quoted characters, within
// maxBraceWork.
func expandQuotedChars(s []quotedChar, limit int) ([]string, bool) {
	work := 0
	return expandQuotedCharsW(s, limit, &work)
}

func plainQuotedChars(s []quotedChar) string {
	b := make([]byte, len(s))
	for i, q := range s {
		b[i] = q.c
	}
	return string(b)
}

func expandQuotedCharsW(s []quotedChar, limit int, work *int) ([]string, bool) {
	if *work += len(s) + 1; *work > maxBraceWork {
		return nil, false
	}
	// match[i] is the "}" that closes the "{" at i, or -1. A "{" that no
	// "}" closes is plain text, and a later one can still make a list.
	match := make([]int, len(s))
	var open []int
	for j := range s {
		match[j] = -1
		if s[j].quoted {
			continue
		}
		switch s[j].c {
		case '{':
			open = append(open, j)
		case '}':
			if n := len(open); n > 0 {
				match[open[n-1]] = j
				open = open[:n-1]
			}
		}
	}
	for i := range s {
		if s[i].c != '{' || s[i].quoted {
			continue
		}
		end := match[i]
		if end < 0 {
			continue
		}
		body := s[i+1 : end]
		if *work += len(body); *work > maxBraceWork {
			return nil, false
		}
		var parts [][]quotedChar
		depth, last := 0, 0
		for j, q := range body {
			if q.quoted {
				continue
			}
			switch q.c {
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
		if len(parts) > 1 {
			for _, part := range parts {
				sub, ok := expandQuotedCharsW(part, limit, work)
				if !ok || len(mids)+len(sub) > limit {
					return nil, false
				}
				mids = append(mids, sub...)
			}
		} else if text := plainQuotedChars(body); !holdsQuoted(body) && (numberSeqRe.MatchString(text) || letterSeqRe.MatchString(text)) {
			if mids = braceSequence(text); mids == nil {
				return nil, false
			}
		} else {
			continue // not a list: bash keeps the braces and reads on
		}
		tails, ok := expandQuotedCharsW(s[end+1:], limit, work)
		if !ok || len(mids)*len(tails) > limit {
			return nil, false
		}
		head := plainQuotedChars(s[:i])
		out := make([]string, 0, len(mids)*len(tails))
		for _, mid := range mids {
			for _, tail := range tails {
				out = append(out, head+mid+tail)
			}
		}
		return out, true
	}
	return []string{plainQuotedChars(s)}, true
}

func holdsQuoted(s []quotedChar) bool {
	for _, q := range s {
		if q.quoted {
			return true
		}
	}
	return false
}

// holdsLiveBrace reports whether the raw text of a word has a "{" that no
// quote covers, or a quote that does not close.
func holdsLiveBrace(raw string) bool {
	chars, ok := quotedChars(raw)
	if !ok {
		return true
	}
	for _, q := range chars {
		if q.c == '{' && !q.quoted {
			return true
		}
	}
	return false
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
