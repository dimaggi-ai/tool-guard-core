package engine

import (
	"os"
	stdpath "path"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// This file holds the reader of a word with a brace list longer than the
// other rules expand (unreadWord). Each word the list makes is walked over
// the file system as the kernel walks it: a symbolic link is followed at
// every part, a ".." gives the physical parent, and a part the check cannot
// know (a variable, a part made by a sequence, a part under /proc) makes the
// directory unknown. A word under an unknown directory is compared with
// every place in a protected path, so it fails closed.

// quoteMark stands where a quote stood in a word, so a path can start
// after it ("x".claude/P is read as .claude/P as well).
const quoteMark = "\x02"

// maxWalkSteps bounds the parts unreadWord walks for one command. A command
// that needs more fails closed.
const maxWalkSteps = 2_000_000

// maxWalkDirs bounds the directories a relative word is read under.
const maxWalkDirs = 64

// maxLinkFollows bounds the symbolic links one walk follows, as the kernel
// does (ELOOP). A walk that needs more fails closed.
const maxLinkFollows = 40

// walkState is where the walk of a path has got to.
type walkState struct {
	unknown bool     // the directory is not known here
	dir     string   // the physical directory when known ("/" is the root)
	rest    []string // names after dir that are not on the disk, or after the unknown directory
	// magic: the unknown directory is a link of /proc or /dev. Such a
	// directory can be the directory of a process, whose names are links
	// to anywhere again (/proc/self/cwd), so a name of rest can stand for
	// any directory.
	magic bool
}

type entryKind uint8

const (
	entryMissing entryKind = iota
	entryDir
	entryLink
	entryOther
	entryError
)

type pathWalker struct {
	memo    map[string]walkState
	entries map[string]entryKind
	lists   map[string][]os.DirEntry
	listErr map[string]bool
	steps   int
	over    bool
}

// walkLookups counts the file-system lookups of every pathWalker (lstat,
// readlink, readdir). Tests read it to bound the cost of a walk.
var walkLookups atomic.Int64

func newPathWalker() *pathWalker {
	return &pathWalker{
		memo:    map[string]walkState{},
		entries: map[string]entryKind{},
		lists:   map[string][]os.DirEntry{},
		listErr: map[string]bool{},
	}
}

func (w *pathWalker) kind(p string) entryKind {
	if k, ok := w.entries[p]; ok {
		return k
	}
	walkLookups.Add(1)
	fi, err := os.Lstat(p)
	var k entryKind
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		k = entryLink
	case err == nil && fi.IsDir():
		k = entryDir
	case err == nil:
		k = entryOther
	case os.IsNotExist(err):
		k = entryMissing
	default:
		k = entryError
	}
	w.entries[p] = k
	return k
}

func joinDir(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// dynamicPart reports whether a part holds an expansion whose text is not
// known: it can be any text, a "/" and a ".." among it.
func dynamicPart(part string) bool {
	return strings.ContainsAny(part, "$`")
}

// wildPart reports whether a part can stand for more than one name: a part
// made by a sequence expression or a file name pattern.
func wildPart(part string) bool {
	return strings.ContainsAny(part, "*?["+numberSeqMark+otherSeqMark)
}

// magicDir reports whether a link at p belongs to /proc or /dev, where the
// target of a link is the directory or file of a process (/proc/self/cwd,
// /dev/fd/3), not a text the check can follow.
func magicDir(p string) bool {
	return strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/dev/")
}

func unknownState() walkState { return walkState{unknown: true} }

func withRest(st walkState, name string) walkState {
	rest := make([]string, len(st.rest), len(st.rest)+1)
	copy(rest, st.rest)
	return walkState{unknown: st.unknown, magic: st.magic, dir: st.dir, rest: append(rest, name)}
}

// step walks one part from st. A part that is not the last one is a
// directory the walk goes into.
func (w *pathWalker) step(st walkState, part string, links int) walkState {
	if w.steps++; w.steps > maxWalkSteps {
		w.over = true
		return unknownState()
	}
	switch {
	case part == "" || part == ".":
		return st
	case part == "..":
		if st.unknown {
			// The parent of a name under an unknown directory is not known
			// either: the name can be a link.
			return unknownState()
		}
		if len(st.rest) > 0 {
			return walkState{dir: st.dir, rest: st.rest[:len(st.rest)-1]}
		}
		return walkState{dir: stdpath.Dir(st.dir)}
	}
	if dynamicPart(part) {
		return unknownState()
	}
	if st.unknown || len(st.rest) > 0 {
		// Under an unknown directory, or under a name that is not on the
		// disk: the name is kept as text.
		return withRest(st, part)
	}
	if wildPart(part) {
		// Which names the part makes is not known. When no name of the
		// directory matches it, the path does not exist and is read as
		// text; when one does, the walk cannot tell which one the word
		// goes through.
		if w.anyEntryMatches(st.dir, part) {
			return unknownState()
		}
		return withRest(st, part)
	}
	p := joinDir(st.dir, part)
	switch w.kind(p) {
	case entryMissing, entryOther:
		// A missing name is made by the command, or the call fails; a
		// file in front of more parts makes the call fail. Either way
		// the text names the path.
		return withRest(st, part)
	case entryDir:
		return walkState{dir: p}
	case entryLink:
		return w.follow(st.dir, p, links)
	default:
		return unknownState()
	}
}

// follow returns where the link at p leads, read from the directory dir it
// stands in.
func (w *pathWalker) follow(dir, p string, links int) walkState {
	if magicDir(p) {
		return walkState{unknown: true, magic: true}
	}
	if links >= maxLinkFollows {
		return unknownState()
	}
	walkLookups.Add(1)
	target, err := os.Readlink(p)
	if err != nil {
		return unknownState()
	}
	target = filepath.ToSlash(target)
	st := walkState{dir: dir}
	if strings.HasPrefix(target, "/") {
		st = walkState{dir: "/"}
	} else if filepath.IsAbs(target) {
		return unknownState() // a drive path: not walked here
	}
	for _, part := range strings.Split(target, "/") {
		if part == "" {
			continue
		}
		if dynamicPart(part) || wildPart(part) {
			// The link holds such a text as plain characters.
			if st.unknown || len(st.rest) > 0 {
				st = withRest(st, part)
				continue
			}
			q := joinDir(st.dir, part)
			switch w.kind(q) {
			case entryDir:
				st = walkState{dir: q}
			case entryLink:
				st = w.follow(st.dir, q, links+1)
			case entryMissing, entryOther:
				st = withRest(st, part)
			default:
				return unknownState()
			}
			continue
		}
		st = w.step(st, part, links+1)
	}
	return st
}

// anyEntryMatches reports whether a name in dir matches the pattern of a
// wild part. A directory that cannot be listed counts as a match.
func (w *pathWalker) anyEntryMatches(dir, part string) bool {
	if w.listErr[dir] {
		return true
	}
	list, ok := w.lists[dir]
	if !ok {
		var err error
		walkLookups.Add(1)
		list, err = os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				w.lists[dir] = nil
				return false
			}
			w.listErr[dir] = true
			return true
		}
		w.lists[dir] = list
	}
	re := partPattern(part)
	if re == nil {
		return true
	}
	for _, e := range list {
		if re.MatchString(e.Name()) {
			return true
		}
	}
	return false
}

// partPattern returns the expression a wild part matches a name with, as
// partsCanMatch reads it, or nil.
func partPattern(part string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, c := range part {
		switch string(c) {
		case "?":
			b.WriteString(`[^/]`)
		case otherSeqMark:
			b.WriteString(`[A-z]`)
		case numberSeqMark:
			b.WriteString(`-?[0-9]+`)
		case "*", "[", "]":
			b.WriteString(`[^/]*`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// walkDir returns where the walk of an absolute directory text ends. The
// walk of each shorter text is kept, so the words of one list, which share
// their directories, walk each of them once.
func (w *pathWalker) walkDir(text string) walkState {
	if st, ok := w.memo[text]; ok {
		return st
	}
	var st walkState
	i := strings.LastIndexByte(text, '/')
	switch {
	case i < 0:
		st = unknownState() // not an absolute text
	case i == 0:
		st = w.step(walkState{dir: "/"}, text[1:], 0)
	default:
		st = w.step(w.walkDir(text[:i]), text[i+1:], 0)
	}
	w.memo[text] = st
	return st
}

// finalStates returns the places an absolute path text can name: the name
// as it stands in its directory and, when that name is a link, the place the
// link leads to.
func (w *pathWalker) finalStates(text string) []walkState {
	i := strings.LastIndexByte(text, '/')
	if i < 0 {
		return []walkState{unknownState()}
	}
	var dir walkState
	if i == 0 {
		dir = walkState{dir: "/"}
	} else {
		dir = w.walkDir(text[:i])
	}
	name := text[i+1:]
	switch {
	case name == "" || name == "." || name == "..":
		return []walkState{w.step(dir, name, 0)}
	case dynamicPart(name):
		return []walkState{unknownState()}
	}
	out := []walkState{withRest(dir, name)}
	if dir.unknown || len(dir.rest) > 0 {
		return out
	}
	if wildPart(name) {
		// A name of the directory that the pattern matches can be a link.
		if w.anyLinkMatches(dir.dir, name) {
			out = append(out, unknownState())
		}
		return out
	}
	p := joinDir(dir.dir, name)
	switch w.kind(p) {
	case entryLink:
		out = append(out, w.follow(dir.dir, p, 0))
	case entryError:
		out = append(out, unknownState())
	}
	return out
}

// anyLinkMatches reports whether a symbolic link in dir matches the pattern
// of a wild part. A directory that cannot be listed counts as a match.
func (w *pathWalker) anyLinkMatches(dir, part string) bool {
	if !w.anyEntryMatches(dir, part) {
		return false
	}
	if w.listErr[dir] {
		return true
	}
	re := partPattern(part)
	if re == nil {
		return true
	}
	for _, e := range w.lists[dir] {
		if re.MatchString(e.Name()) && e.Type()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// protectedForm is one protected path as parts, with whether it is a file
// on the disk: nothing can stand under a file.
type protectedForm struct {
	parts []string
	file  bool
}

func protectedForms(prefixes []string) []protectedForm {
	var out []protectedForm
	for _, prefix := range prefixes {
		file := false
		if fi, err := os.Stat(prefix); err == nil && !fi.IsDir() {
			file = true
		}
		out = append(out, protectedForm{parts: pathParts(filepath.ToSlash(prefix)), file: file})
	}
	return out
}

// stateNamesProtected reports whether the place a walk ends at can be a
// protected path, a path under one, or a directory above one. A place under
// an unknown directory is compared with every part of the protected path:
// the unknown directory can be any directory above it.
func stateNamesProtected(st walkState, forms []protectedForm) bool {
	if st.unknown {
		// Under a link of /proc or /dev each name of rest can be a link
		// to any directory, so the names after it are compared too.
		tails := 1
		if st.magic && len(st.rest) > 0 {
			tails = len(st.rest)
		}
		for j := 0; j < tails; j++ {
			rest := st.rest[j:]
			for _, f := range forms {
				last := len(f.parts)
				if f.file && len(rest) > 0 {
					last-- // a name cannot stand under a file
				}
				for k := 0; k <= last; k++ {
					if partsCanMatch(rest, f.parts[k:]) {
						return true
					}
				}
			}
		}
		return false
	}
	full := pathParts(st.dir)
	full = append(full, st.rest...)
	if procPathUnknown("/"+strings.Join(full, "/")) || procDirUnknown("/"+strings.Join(full, "/")) {
		return true
	}
	for _, f := range forms {
		if partsCanMatch(full, f.parts) {
			return true
		}
	}
	return false
}

// wordSplitChars are the characters after which a path can start in one
// word: characters that are not part of a path (=, :, @, a comma, +, %), a
// quote, and the blanks and shell characters of a command text that another
// command reads again (eval 'cmd PATH', trap, su -c, python3 w.py\ PATH).
const wordSplitChars = "=:@,+%" + quoteMark + " \t\n;|&()<>`"

// maxWordStarts bounds the places a path can start in one word. A word with
// more fails closed.
const maxWordStarts = 256

// maxUnreadStarts bounds the texts unreadWord walks for one command. A
// command that needs more fails closed.
const maxUnreadStarts = 100_000

// extglobOpenRe matches the start of an extglob pattern: @(, !(, +(, *(, ?(.
var extglobOpenRe = regexp.MustCompile(`[@!+*?]\(`)

// maxUnreadWordLen bounds the length of a word that unreadWord expands. A
// longer word with a long brace list fails closed.
const maxUnreadWordLen = 8192

// wordStarts returns the texts in one word made by a brace list at which a
// path can start: the word itself, the text after each character of
// wordSplitChars, the text after the letters of a short option
// (tar -cfPATH), and the text from the first "/" or "~" of an option. ok is
// false when there are more than maxWordStarts places.
func wordStarts(e string) ([]string, bool) {
	var out []string
	seen := map[string]bool{}
	over := false
	add := func(v string) {
		if over {
			return
		}
		v = strings.ReplaceAll(v, quoteMark, "")
		if v != "" && !seen[v] {
			if len(out) >= maxWordStarts {
				over = true
				return
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	add(e)
	for i := 0; i < len(e) && !over; i++ {
		if strings.IndexByte(wordSplitChars, e[i]) >= 0 {
			add(e[i+1:])
		}
	}
	if strings.HasPrefix(e, "-") {
		if j := strings.IndexAny(e, "/~"); j > 0 {
			add(e[j:])
		}
		// The letters of a cluster stand before the value: -cvfPATH puts
		// PATH after any of them.
		for k := 2; k < len(e) && e[k-1] != '/' && !over; k++ {
			add(e[k:])
		}
	}
	return out, !over
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

// unquoteOnce returns the text a command such as eval gets from the raw
// text of a word: the quotes and backslashes of one level removed. ok is
// false for a quote that does not close.
func unquoteOnce(raw string) (string, bool) {
	chars, ok := quotedChars(raw)
	if !ok {
		return "", false
	}
	return plainQuotedChars(chars), true
}

// unreadWord returns a word of the command that the name rule cannot read
// and that can be a protected path: a word with a brace list of more words
// than maxBraceWords, and the name of the shell option `nocaseglob`. The
// word is expanded here up to maxUnreadBraceWords words, as bash expands it
// and, when the word holds a command text (eval 'cmd PATH'), as the command
// that reads the text again expands it. Each word it makes is read from
// every place a path can start in it, under the home directory for a
// tilde, and under the working directory, each base and each directory the
// command names for a relative path. The path is walked over the file
// system (pathWalker) and compared with the protected paths part by part. A
// word that makes more words, that holds $'...' text, a control character,
// an extglob pattern, or whose walk needs more steps than the check reads,
// is returned without a comparison.
func unreadWord(cmd string, toks []shellToken, bases, prefixes []string) string {
	var walker *pathWalker
	var forms []protectedForm
	var dirs, homes []string
	var dirsOver, dirUnknown bool
	starts := 0
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
		if len(t.raw) > maxUnreadWordLen {
			if !holdsLiveBrace(t.raw) {
				continue // a long quoted text such as JSON makes no list
			}
			return word
		}
		if made, ok := expandBraces(homeVarRe.ReplaceAllString(t.raw, "~")); ok && !holdsBraceList(made) {
			continue // the other rules read each word of the list
		}
		if strings.Contains(t.raw, "$'") || strings.Contains(t.raw, "$\"") {
			return word
		}
		for i := 0; i < len(t.raw); i++ {
			if t.raw[i] < 0x08 {
				return word // a control byte can stand for a mark of this reader
			}
		}
		if extglobOpenRe.MatchString(cmd) {
			return word // @(...) and the like: a pattern the check does not expand
		}
		readings := []string{t.raw}
		if text, ok := unquoteOnce(t.raw); ok && text != t.raw && strings.ContainsAny(text, " \t\n;|&()<>`") {
			readings = append(readings, text)
		}
		var made []string
		for _, r := range readings {
			marked, ok := markQuotes(r)
			if !ok {
				return word
			}
			marked = homeVarRe.ReplaceAllString(marked, "~")
			words, ok := expandLongBraces(marked, maxUnreadBraceWords)
			if !ok || len(made)+len(words) > maxUnreadBraceWords {
				return word
			}
			for _, w := range words {
				made = append(made, plainMarkRestore.Replace(w))
			}
		}
		if walker == nil {
			walker = newPathWalker()
			forms = protectedForms(prefixes)
			dirs, dirsOver, dirUnknown = walkDirs(toks, bases)
			homes = walkHomes(toks)
		}
		if dirsOver {
			return word
		}
		for _, e := range made {
			list, ok := wordStarts(e)
			if !ok {
				return word
			}
			for _, s := range list {
				if dirUnknown && (s == ".." || strings.HasPrefix(s, "../")) {
					return word // under a directory the command names by a variable
				}
				for _, text := range startTexts(s, dirs, homes) {
					if starts++; starts > maxUnreadStarts {
						return word
					}
					var states []walkState
					if text == "" {
						states = []walkState{unknownState()}
					} else {
						states = walker.finalStates(text)
					}
					for _, st := range states {
						if stateNamesProtected(st, forms) {
							return word
						}
					}
					if walker.over {
						return word
					}
				}
			}
		}
	}
	return ""
}

// startTexts returns the absolute texts a path that starts with s can be:
// s itself when absolute, s under each home directory for a tilde form, and
// s under each directory of dirs when relative. "" stands for a path under a
// directory this check does not know (~NAME, ~-).
func startTexts(s string, dirs, homes []string) []string {
	switch {
	case s == "~" || strings.HasPrefix(s, "~/"):
		var out []string
		for _, h := range homes {
			out = append(out, h+"/"+s[1:])
		}
		if len(out) == 0 {
			return []string{""}
		}
		return out
	case s == "~+" || strings.HasPrefix(s, "~+/"):
		return startTexts(strings.TrimPrefix(strings.TrimPrefix(s, "~+"), "/"), dirs, homes)
	case strings.HasPrefix(s, "~"):
		return []string{""}
	case strings.HasPrefix(s, "/"):
		return []string{s}
	case filepath.IsAbs(s) || volumeNameOf(s) != "":
		return []string{""} // a drive path: not walked here
	}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, d+"/"+s)
	}
	return out
}

// walkHomes returns the home directories a tilde can stand for: the home
// directory of the shell and each value the command gives HOME.
func walkHomes(toks []shellToken) []string {
	var out []string
	if h, err := shellHomeDir(); err == nil && h != "" {
		out = append(out, strings.TrimRight(filepath.ToSlash(h), "/"))
	}
	for _, t := range toks {
		if t.kind == tokWord && strings.HasPrefix(t.value, "HOME=") {
			if v := strings.TrimRight(t.value[len("HOME="):], "/"); strings.HasPrefix(v, "/") && !containsString(out, v) {
				out = append(out, v)
			}
		}
	}
	return out
}

// walkDirs returns the directories a relative word is read under: the
// working directory, each base, and each directory the command names (env
// -C DIR, env -CDIR, --chdir=DIR, tar -C DIR, cd DIR, cd ~/DIR): the command
// can run in any of them. over is true when there are more than maxWalkDirs
// of them; the caller fails closed. unknown is true when the command names a
// directory by a word the check cannot read (cd $D, env -C $D).
func walkDirs(toks []shellToken, bases []string) (out []string, over, unknown bool) {
	add := func(d string) {
		d = filepath.ToSlash(d)
		if d != "/" {
			d = strings.TrimRight(d, "/")
		}
		if !strings.HasPrefix(d, "/") || containsString(out, d) {
			return
		}
		if len(out) >= maxWalkDirs {
			over = true
			return
		}
		out = append(out, d)
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	homes := walkHomes(toks)
	for _, base := range bases {
		if base == "~" || strings.HasPrefix(base, "~/") {
			for _, h := range homes {
				add(h + base[1:])
			}
			continue
		}
		for _, cand := range literalPathCandidates(base) {
			add(cand)
		}
	}
	roots := append([]string{}, out...)
	for i, t := range toks {
		if t.kind != tokWord {
			continue
		}
		if t.unresolved {
			prev := ""
			if i > 0 && toks[i-1].kind == tokWord {
				prev = toks[i-1].value
			}
			switch {
			case prev == "cd" || prev == "pushd" || prev == "-C" || prev == "--chdir" || prev == "--directory",
				strings.HasPrefix(t.value, "-C"), strings.HasPrefix(t.value, "--chdir="), strings.HasPrefix(t.value, "--directory="):
				unknown = true
			}
			continue
		}
		if t.value == "" || strings.ContainsAny(t.value, "{}*?[") {
			continue
		}
		var vals []string
		v := t.value
		switch {
		case strings.HasPrefix(v, "--"):
			if i := strings.IndexByte(v, '='); i >= 0 {
				vals = []string{v[i+1:]} // --chdir=DIR
			}
		case strings.HasPrefix(v, "-"):
			// A short option with its value glued on: -CDIR, -xCDIR.
			for k := 2; k < len(v) && k <= 16 && v[k-1] != '/'; k++ {
				vals = append(vals, v[k:])
			}
		default:
			vals = []string{v}
		}
		for _, v := range vals {
			if v == "" || len(v) > maxResolvePathLen {
				continue
			}
			var cands []string
			switch {
			case strings.HasPrefix(v, "/"):
				cands = []string{v}
			case v == "~" || strings.HasPrefix(v, "~/"):
				for _, h := range homes {
					cands = append(cands, h+v[1:])
				}
			default:
				for _, r := range roots {
					cands = append(cands, r+"/"+v)
				}
			}
			for _, c := range cands {
				if fi, err := os.Stat(c); err == nil && fi.IsDir() {
					add(c)
				}
			}
		}
	}
	return out, over, unknown
}
