package engine

// protect_net.go is the check of a shell command against the protected
// paths. Each stage gives one of three answers:
//
//	Names       some reading of the text reaches a protected path
//	CannotName  every reading reaches a known place that is not protected
//	Unknown     the stage could not resolve a reading
//
// A stage that meets syntax it does not model, stops early or runs out of
// budget gives Unknown, never CannotName. Unknown denies when the protected
// path is possible (the rules in netCtx.check).
//
// The text is read in three ways:
//
//   - level 1: the words of tokenizeShell, with their quotes, for redirect
//     targets and the operands of programs that write;
//   - sigma: the raw text with every backslash-newline pair, quote and
//     backslash deleted. Quote removal applied any number of times and then
//     sigma gives the same text as sigma alone, so this one reading covers
//     eval, trap, sh -c, xargs, source and nested eval at any depth;
//   - decoded: quotes removed, the escapes \xHH, \NNN, \uHHHH and
//     \UHHHHHHHH decoded, then the other backslashes removed.
//
// A brace list in a word is expanded exactly when the word is well formed
// and the expansion is small. Otherwise the word becomes a list of atoms
// that holds every expansion of bash: the text before the first brace and
// after the last one is required, every piece in between is optional. Paths
// are matched against the atoms with an automaton, one directory at a time.

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// netMaxSteps bounds the work of one top-level check, nested texts
	// included.
	netMaxSteps = 2_000_000
	// netMaxLookups bounds the file system calls of one top-level check.
	netMaxLookups = 10_000
	// netMaxList is the largest number of words a brace list may make.
	// More words than this is Unknown.
	netMaxList = 4096
	// netMaxExpandBytes bounds the text an exact brace expansion may
	// make. Above it the word is read as atoms.
	netMaxExpandBytes = 256 << 10
	// netMaxNameLen is the longest file name a file system takes.
	netMaxNameLen = 255
)

// netBudget is the work counter of one top-level check.
type netBudget struct {
	steps   int
	lookups int
	over    bool
}

func (b *netBudget) charge(n int) bool {
	b.steps += n
	if b.steps > netMaxSteps {
		b.over = true
	}
	return !b.over
}

func (b *netBudget) lookup() bool {
	b.lookups++
	if b.lookups > netMaxLookups {
		b.over = true
	}
	return !b.over
}

// Causes of an Unknown answer.
const (
	causeDyn    = 1 << iota // a variable or another expansion
	causeMagic              // a link of /proc or /dev, ~user, ~+, ~-
	causeBase               // a directory change the check cannot resolve
	causeList               // a brace list of more than netMaxList words
	causeRemote             // a base on a FUSE or network mount
)

// netRemoteCwdReason is the reason for a command whose relative path is
// read from a directory on a FUSE or network mount: the check does not
// look into such a mount, so it cannot know where the path leads.
const netRemoteCwdReason = "a command whose working directory is on a network or FUSE file system"

// unknownReason returns the reason for a deny with the causes cause: the
// text, or netRemoteCwdReason when a base is on a remote mount.
func unknownReason(text string, cause int) string {
	if cause&causeRemote != 0 {
		return netRemoteCwdReason
	}
	return shortRaw(text)
}

// mchar is one character of a reading.
type mchar struct {
	c  byte
	k  uint8 // mLit, mMeta or mDyn
	st bool  // a path may start at this character
	en bool  // a path may end after this character
}

const (
	mLit  uint8 = iota // a literal character
	mMeta              // { } , * ? [ ] outside quotes
	mDyn               // an expansion: any text
)

type atomKind uint8

const (
	aLit    atomKind = iota // the text s
	aRange                  // one character from lo to hi
	aQ                      // one character other than /
	aStar                   // any text without /
	aDyn                    // any text
	aDigits                 // any text of digits and -
)

type atom struct {
	kind   atomKind
	opt    bool
	s      string
	lo, hi byte
	// startAt: a path may start at this atom. endAt: a path may end
	// after it.
	startAt, endAt bool
	// skipTo, when above 0: the atoms from this one to skipTo are
	// optional together. Text between two brace marks is kept whole.
	skipTo int32
}

// netPattern is a list of atoms read as an automaton. A position is an
// atom and an offset in it: start[i]+k. The position accept is after the
// last atom.
type netPattern struct {
	atoms  []atom
	start  []int32
	atomOf []int32
	offOf  []int32
	isEnd  []bool
	starts []int32
	accept int32
	fold   bool
	hasDyn bool
	// big: the pattern is one word of a brace list of more than
	// maxBraceWords words. Such a word is read without letter case, and a
	// directory above a protected path that it names counts as a name.
	big   bool
	mark  []uint32
	gen   uint32
	stack []int32
}

func newNetPattern(atoms []atom, fold bool) *netPattern {
	p := &netPattern{atoms: atoms, fold: fold}
	p.start = make([]int32, len(atoms)+1)
	n := int32(0)
	for i, a := range atoms {
		p.start[i] = n
		if a.kind == aLit {
			n += int32(len(a.s))
		} else {
			n++
		}
		if a.kind == aDyn {
			p.hasDyn = true
		}
	}
	p.start[len(atoms)] = n
	p.accept = n
	p.atomOf = make([]int32, n)
	p.offOf = make([]int32, n)
	for i, a := range atoms {
		size := int32(1)
		if a.kind == aLit {
			size = int32(len(a.s))
		}
		for k := int32(0); k < size; k++ {
			p.atomOf[p.start[i]+k] = int32(i)
			p.offOf[p.start[i]+k] = k
		}
	}
	p.isEnd = make([]bool, n+1)
	p.isEnd[n] = true
	p.starts = []int32{0}
	for i, a := range atoms {
		if a.startAt && i > 0 {
			p.starts = append(p.starts, p.start[i])
		}
		if a.endAt {
			p.isEnd[p.start[i+1]] = true
		}
	}
	p.mark = make([]uint32, n+1)
	return p
}

func (p *netPattern) newGen() {
	p.gen++
	if p.gen == 0 {
		clear(p.mark)
		p.gen = 1
	}
}

// addClosure adds q and every position it reaches without a character.
func (p *netPattern) addClosure(out []int32, q int32) []int32 {
	p.stack = append(p.stack[:0], q)
	for len(p.stack) > 0 {
		x := p.stack[len(p.stack)-1]
		p.stack = p.stack[:len(p.stack)-1]
		if p.mark[x] == p.gen {
			continue
		}
		p.mark[x] = p.gen
		out = append(out, x)
		if x == p.accept || p.offOf[x] != 0 {
			continue
		}
		i := p.atomOf[x]
		a := &p.atoms[i]
		if a.opt || a.kind == aStar || a.kind == aDyn || a.kind == aDigits {
			p.stack = append(p.stack, p.start[i+1])
		}
		if a.skipTo > 0 {
			p.stack = append(p.stack, p.start[a.skipTo])
		}
	}
	return out
}

func (p *netPattern) closureOf(qs []int32) []int32 {
	p.newGen()
	var out []int32
	for _, q := range qs {
		out = p.addClosure(out, q)
	}
	slices.Sort(out)
	return out
}

func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// next is the position after x on the character c, or -1.
func (p *netPattern) next(x int32, c byte, dyn bool) int32 {
	if x == p.accept {
		return -1
	}
	i := p.atomOf[x]
	a := &p.atoms[i]
	switch a.kind {
	case aLit:
		ch := a.s[p.offOf[x]]
		if ch == c || (p.fold && foldByte(ch) == foldByte(c)) {
			return x + 1
		}
	case aRange:
		if (c >= a.lo && c <= a.hi) || (p.fold && ((foldByte(c) >= a.lo && foldByte(c) <= a.hi) || (c >= 'a' && c <= 'z' && c-'a'+'A' >= a.lo && c-'a'+'A' <= a.hi))) {
			return p.start[i+1]
		}
	case aQ:
		if c != '/' {
			return p.start[i+1]
		}
	case aStar:
		if c != '/' {
			return x
		}
	case aDigits:
		if c == '-' || (c >= '0' && c <= '9') {
			return x
		}
	case aDyn:
		if dyn {
			return x
		}
	}
	return -1
}

// step is the set of positions after the character c.
func (p *netPattern) step(set []int32, c byte, dyn bool) []int32 {
	p.newGen()
	var out []int32
	for _, x := range set {
		if y := p.next(x, c, dyn); y >= 0 {
			out = p.addClosure(out, y)
		}
	}
	slices.Sort(out)
	return out
}

func (p *netPattern) steps(b *netBudget, set []int32, s string) []int32 {
	for i := 0; i < len(s) && len(set) > 0; i++ {
		if !b.charge(len(set) + 1) {
			return nil
		}
		set = p.step(set, s[i], false)
	}
	return set
}

func (p *netPattern) accepts(set []int32) bool {
	for _, x := range set {
		if p.isEnd[x] {
			return true
		}
	}
	return false
}

// spells reports whether the set can read rel and then end or go on with
// a slash.
func (p *netPattern) spells(b *netBudget, set []int32, rel string) bool {
	set = p.steps(b, set, rel)
	if len(set) == 0 {
		return false
	}
	return p.accepts(set) || len(p.step(set, '/', false)) > 0
}

// fixedName returns the name the set must read next, when there is only
// one, and the set after it.
func (p *netPattern) fixedName(b *netBudget, set []int32) (string, []int32, bool) {
	var buf []byte
	for {
		if len(set) != 1 {
			return "", nil, false
		}
		x := set[0]
		if x == p.accept {
			return string(buf), set, len(buf) > 0
		}
		if p.isEnd[x] {
			return "", nil, false
		}
		a := &p.atoms[p.atomOf[x]]
		if a.kind != aLit {
			return "", nil, false
		}
		ch := a.s[p.offOf[x]]
		if ch == '/' {
			return string(buf), set, len(buf) > 0
		}
		buf = append(buf, ch)
		if !b.charge(1) {
			return "", nil, false
		}
		set = p.step(set, ch, false)
	}
}

// anyPart returns the positions after one or more characters other than /,
// expansions included.
func (p *netPattern) anyPart(b *netBudget, set []int32) []int32 {
	seen := map[int32]bool{}
	var out []int32
	cur := set
	for len(cur) > 0 {
		var nxt []int32
		for c := 0; c < 256; c++ {
			if c == '/' {
				continue
			}
			if !b.charge(len(cur) + 1) {
				return out
			}
			for _, y := range p.step(cur, byte(c), true) {
				if !seen[y] {
					seen[y] = true
					out = append(out, y)
					nxt = append(nxt, y)
				}
			}
		}
		cur = nxt
	}
	return out
}

// procMagic reports whether the pattern, read from /proc (or from the task
// directory of a process when top is false), can name a directory of a
// process: any name, then cwd, root, exe, fd or map_files.
func (p *netPattern) procMagic(b *netBudget, set []int32, top bool) bool {
	after := p.step(p.anyPart(b, set), '/', true)
	if len(after) == 0 {
		return false
	}
	for _, name := range []string{"cwd", "root", "exe", "fd", "map_files"} {
		if e := p.steps(b, after, name); len(e) > 0 && (p.accepts(e) || len(p.step(e, '/', false)) > 0) {
			return true
		}
	}
	if top {
		if task := p.step(p.steps(b, after, "task"), '/', false); len(task) > 0 {
			return p.procMagic(b, task, false)
		}
	}
	return false
}

// roamsTree reports whether the pattern, read from a directory, names
// both its parent (..) and a child of any name of any length. A directory
// change to such an operand can reach every directory.
func (p *netPattern) roamsTree(b *netBudget) bool {
	init := p.closureOf(p.starts)
	for _, name := range []string{"..", "x", "x9-_qzA.x9-_qzA.x9-_qzA"} {
		if !p.accepts(p.steps(b, init, name)) {
			return false
		}
	}
	return true
}

// hasName reports whether the pattern holds a literal character other than
// . and /.
func (p *netPattern) hasName() bool {
	for _, a := range p.atoms {
		if a.kind == aLit && strings.Trim(a.s, "./") != "" {
			return true
		}
	}
	return false
}

// literal returns the text of a pattern that is one fixed word with one
// start and one end.
func (p *netPattern) literal() (string, bool) {
	if len(p.starts) != 1 || p.fold {
		return "", false
	}
	var sb strings.Builder
	for i, a := range p.atoms {
		if a.kind != aLit || a.opt || a.skipTo > 0 || (a.endAt && i != len(p.atoms)-1) {
			return "", false
		}
		sb.WriteString(a.s)
	}
	if sb.Len() == 0 {
		return "", false
	}
	return sb.String(), true
}

// walkLiteral is walk for a fixed word: the place it names is resolved
// directly.
func (c *netCtx) walkLiteral(lit, base string, collect, strict bool) (names, magic bool, dirs []string) {
	c.b.charge(len(lit))
	from := base
	if strings.HasPrefix(lit, "/") {
		from = "/"
	} else if base == "" {
		return
	}
	if remote(from) {
		// Not looked into: every place under it is unknown.
		return false, true, nil
	}
	place, kind, mg := c.fs.resolve(from, lit, 0)
	if mg {
		if collect && remote(place) {
			// A directory change onto a remote mount: that place is a
			// base, where every relative path is unknown.
			return false, true, []string{place}
		}
		return false, true, nil
	}
	if collect {
		if kind == kDir && place != base {
			dirs = append(dirs, place)
		}
		return
	}
	for _, t := range c.targets {
		if c.atOrUnder(place, t.path) {
			if !strict && from == base && (place == base || (kind == kMissing && c.atOrUnder(base, t.path))) {
				continue
			}
			return true, false, nil
		}
	}
	return
}

func setKey(dir string, set []int32) string {
	var sb strings.Builder
	sb.WriteString(dir)
	sb.WriteByte(0)
	for _, x := range set {
		sb.WriteString(strconv.FormatInt(int64(x), 36))
		sb.WriteByte(',')
	}
	return sb.String()
}

// ---- building atoms ----

// atomsOf turns characters into atoms. opt makes them optional. flags
// keeps the start and end marks.
func atomsOf(out []atom, ms []mchar, opt, flags bool) []atom {
	// The open literal is built in buf and stored when it ends, so a long
	// literal costs linear time.
	openLit := false
	var buf []byte
	flush := func() {
		if openLit {
			out[len(out)-1].s = string(buf)
			buf = buf[:0]
		}
		openLit = false
	}
	closes := closingBrackets(ms)
	for i := 0; i < len(ms); i++ {
		m := ms[i]
		st := flags && m.st
		switch {
		case m.k == mDyn:
			flush()
			if n := len(out); n > 0 && out[n-1].kind == aDyn && out[n-1].opt == opt && !st && !out[n-1].endAt {
				break
			}
			out = append(out, atom{kind: aDyn, opt: opt, startAt: st})
		case m.k == mMeta && m.c == '*':
			flush()
			out = append(out, atom{kind: aStar, opt: opt, startAt: st})
		case m.k == mMeta && m.c == '?':
			flush()
			out = append(out, atom{kind: aQ, opt: opt, startAt: st})
		case m.k == mMeta && m.c == '[' && closes[i] > i:
			// A bracket expression matches one character, and its own
			// text when no file matches. A star holds both.
			flush()
			j := closes[i]
			for k := i + 1; k+1 < j; k++ {
				if ms[k].c == '[' && strings.IndexByte(".=:", ms[k+1].c) >= 0 {
					// A collating element, an equivalence class or a
					// character class ([[.k.]]) has a ] of its own: the
					// star runs to the end of the part.
					for j+1 < len(ms) && ms[j+1].c != '/' {
						j++
					}
					break
				}
			}
			out = append(out, atom{kind: aStar, opt: opt, startAt: st})
			for k := i + 1; k <= j; k++ {
				if flags && ms[k].en {
					out[len(out)-1].endAt = true
				}
			}
			i = j
			m = ms[j]
		default:
			if !openLit || st {
				flush()
				out = append(out, atom{kind: aLit, opt: opt, startAt: st})
				openLit = true
			}
			buf = append(buf, m.c)
		}
		if flags && m.en {
			out[len(out)-1].endAt = true
			flush()
		}
	}
	flush()
	return out
}

// closingBrackets returns, for each index i, the index of the ] that
// closes a [ at i, or -1: the first ] after i+1 with no / before it. It
// reads the characters once from the end.
func closingBrackets(ms []mchar) []int {
	out := make([]int, len(ms))
	// next: the first ] at or after a position, before any /; next2 the
	// one after it.
	next, next2 := -1, -1
	for i := len(ms) - 1; i >= 0; i-- {
		// The answer for i is the first ] at j >= i+2.
		switch {
		case next >= i+2:
			out[i] = next
		case next2 >= i+2:
			out[i] = next2
		default:
			out[i] = -1
		}
		if ms[i].c == '/' {
			next, next2 = -1, -1
		} else if ms[i].k == mMeta && ms[i].c == ']' {
			next, next2 = i, next
		}
	}
	return out
}

// bitem is one item of a parsed brace word: a character, a list of
// alternatives, or a sequence.
type bitem struct {
	ch    mchar
	alts  [][]bitem
	seq   []string
	isSeq bool
	group bool
}

// wellFormedBraces reports whether every { and } outside quotes is
// paired and nested.
// netMaxBraceDepth bounds the nesting of brace groups the exact reading
// parses. A deeper word is not well formed for it.
const netMaxBraceDepth = 128

func wellFormedBraces(ms []mchar) (bool, bool) {
	// any is read over the whole word: a } before the first { must not
	// hide the lists after it.
	depth, any, ok := 0, false, true
	for _, m := range ms {
		if m.k != mMeta {
			continue
		}
		switch m.c {
		case '{':
			depth++
			any = true
			if depth > netMaxBraceDepth {
				// Deeper groups are read as optional pieces.
				ok = false
			}
		case '}':
			depth--
			if depth < 0 {
				ok = false
				depth = 0
			}
		}
	}
	return ok && depth == 0, any
}

// parseBraces parses a well formed word as bash does: a group with a
// comma at its level is a list, a valid {x..y[..n]} is a sequence, and
// any other group is text with its inner groups still expanded.
func parseBraces(b *netBudget, ms []mchar, i int, inGroup bool) ([][]bitem, int) {
	var alts [][]bitem
	var cur []bitem
	for i < len(ms) {
		// Over the budget the parse stops; the caller sees b.over.
		if !b.charge(1) {
			return append(alts, cur), len(ms)
		}
		m := ms[i]
		if m.k == mMeta && m.c == '{' {
			galts, j := parseBraces(b, ms, i+1, true)
			switch {
			case len(galts) > 1:
				cur = append(cur, bitem{alts: galts, group: true})
			default:
				body := galts[0]
				if seq, ok := braceSeqItems(body); ok {
					cur = append(cur, bitem{seq: seq, isSeq: true, group: true})
					// Keep the start mark of the text.
					cur[len(cur)-1].ch = m
				} else if b.charge(len(body)) {
					// The copy of the body is charged, so deep groups of
					// one word cost the budget and not the time limit.
					cur = append(cur, bitem{ch: m})
					cur = append(cur, body...)
					if j < len(ms) {
						cur = append(cur, bitem{ch: ms[j]})
					}
				}
			}
			i = j + 1
			continue
		}
		if inGroup && m.k == mMeta && m.c == ',' {
			alts = append(alts, cur)
			cur = nil
			i++
			continue
		}
		if inGroup && m.k == mMeta && m.c == '}' {
			return append(alts, cur), i
		}
		cur = append(cur, bitem{ch: m})
		i++
	}
	return append(alts, cur), i
}

var braceIntSeqRe = regexp.MustCompile(`^([-+]?[0-9]+)\.\.([-+]?[0-9]+)(\.\.([-+]?[0-9]+))?$`)
var braceCharSeqRe = regexp.MustCompile(`^([A-Za-z])\.\.([A-Za-z])(\.\.([-+]?[0-9]+))?$`)

// braceSeqItems returns the words of a sequence body, or ok false. A
// sequence of more than netMaxList+1 words returns a nil list with ok.
func braceSeqItems(body []bitem) ([]string, bool) {
	// The body has no length limit, as in bash. The read stops at the
	// first character a sequence cannot hold, so a deep group of groups
	// is read in time linear in its length.
	var sb strings.Builder
	for _, it := range body {
		if it.group || it.ch.k == mDyn || !isSeqByte(it.ch.c) {
			return nil, false
		}
		sb.WriteByte(it.ch.c)
	}
	return braceSequence2(sb.String())
}

// isSeqByte reports whether c can be in the body of a sequence:
// {x..y..n}.
func isSeqByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '-'
}

// versionDependentSeq reports whether the characters hold a sequence that
// versions of bash expand in different ways: one with an increment, or
// with a zero-padded number, which bash 3 keeps as text or reads without
// the padding, or with a number that does not fit in 32 bits, which some
// versions read with overflow. Such a word is read with the brace atoms,
// which hold every expansion.
func versionDependentSeq(ms []mchar) bool {
	isBrace := func(m mchar) bool {
		return m.k == mMeta && (m.c == '{' || m.c == '}' || m.c == ',')
	}
	for i := 0; i < len(ms); i++ {
		if !(ms[i].k == mMeta && ms[i].c == '{') {
			continue
		}
		j := i + 1
		for j < len(ms) && !isBrace(ms[j]) {
			j++
		}
		if j >= len(ms) || ms[j].c != '}' {
			continue
		}
		body := make([]byte, 0, j-i-1)
		for _, m := range ms[i+1 : j] {
			body = append(body, m.c)
		}
		if m := braceCharSeqRe.FindSubmatch(body); m != nil && len(m[4]) > 0 {
			return true
		}
		m := braceIntSeqRe.FindSubmatch(body)
		if m == nil {
			continue
		}
		if len(m[4]) > 0 {
			return true
		}
		for _, e := range [][]byte{m[1], m[2]} {
			t := strings.TrimLeft(string(e), "+-")
			if len(t) > 1 && t[0] == '0' {
				return true
			}
			if v, err := strconv.ParseInt(string(e), 10, 64); err != nil || v > math.MaxInt32 || v < math.MinInt32 {
				return true
			}
		}
	}
	return false
}

// braceSequence2 returns the words of a sequence as bash makes them. A
// sequence of netMaxList words or more returns an empty, non-nil list: the
// readers read it as any digits. A number or an increment bash does not
// read (out of the int64 range, or the increment -2^63) or a span over
// 2^63-1 makes no sequence, as in bash, which keeps the text. The count is computed without
// overflow and the loop runs at most netMaxList times.
func braceSequence2(s string) ([]string, bool) {
	if m := braceIntSeqRe.FindStringSubmatch(s); m != nil {
		lo, err1 := strconv.ParseInt(m[1], 10, 64)
		hi, err2 := strconv.ParseInt(m[2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, false
		}
		inc := uint64(1)
		if m[4] != "" {
			v, err := strconv.ParseInt(m[4], 10, 64)
			if err != nil || v == math.MinInt64 {
				return nil, false
			}
			if v < 0 {
				v = -v
			}
			if v != 0 {
				inc = uint64(v)
			}
		}
		var span uint64
		if hi >= lo {
			span = uint64(hi) - uint64(lo)
		} else {
			span = uint64(lo) - uint64(hi)
		}
		if span > math.MaxInt64 {
			// bash computes the span in intmax_t; when it overflows,
			// bash makes no sequence and keeps the text.
			return nil, false
		}
		if span/inc >= netMaxList {
			return []string{}, true // too long: read as digits
		}
		count := span/inc + 1
		width := 0
		for _, e := range []string{m[1], m[2]} {
			t := strings.TrimLeft(e, "+-")
			if len(t) > 1 && t[0] == '0' && len(e) > width {
				width = len(e)
			}
		}
		out := make([]string, 0, count)
		for k := uint64(0); k < count; k++ {
			// lo + k*inc (or lo - k*inc) stays between lo and hi, so it
			// does not overflow when done in uint64.
			var v int64
			if hi >= lo {
				v = int64(uint64(lo) + k*inc)
			} else {
				v = int64(uint64(lo) - k*inc)
			}
			t := strconv.FormatInt(v, 10)
			if width > 0 {
				neg := strings.HasPrefix(t, "-")
				t = strings.TrimPrefix(t, "-")
				w := width
				if neg {
					w--
				}
				for len(t) < w {
					t = "0" + t
				}
				if neg {
					t = "-" + t
				}
			}
			out = append(out, t)
		}
		return out, true
	}
	if m := braceCharSeqRe.FindStringSubmatch(s); m != nil {
		lo, hi := int(m[1][0]), int(m[2][0])
		inc := 1
		if m[4] != "" {
			v, err := strconv.ParseInt(m[4], 10, 64)
			if err != nil || v == math.MinInt64 {
				return nil, false
			}
			if v < 0 {
				v = -v
			}
			if v > 256 {
				v = 256 // any larger increment makes the first letter only
			}
			if v != 0 {
				inc = int(v)
			}
		}
		var out []string
		if lo <= hi {
			for c := lo; c <= hi; c += inc {
				out = append(out, string(rune(c)))
			}
		} else {
			for c := lo; c >= hi; c -= inc {
				out = append(out, string(rune(c)))
			}
		}
		return out, true
	}
	return nil, false
}

// braceCounts returns the number of words of the items: lists only
// (sequences count as one), and all groups. Both stop at limit+1.
func braceCounts(items []bitem, limit int) (lists, all int) {
	lists, all = 1, 1
	for _, it := range items {
		if !it.group {
			continue
		}
		l, a := 0, 0
		if it.isSeq {
			l = 1
			a = len(it.seq)
			if a == 0 {
				a = limit + 1
			}
		} else {
			for _, alt := range it.alts {
				al, aa := braceCounts(alt, limit)
				l += al
				a += aa
				if l > limit {
					l = limit + 1
				}
				if a > limit {
					a = limit + 1
				}
			}
		}
		lists *= max(l, 1)
		all *= max(a, 1)
		if lists > limit {
			lists = limit + 1
		}
		if all > limit {
			all = limit + 1
		}
	}
	return lists, all
}

// expandItems makes every word of the items.
func expandItems(b *netBudget, items []bitem) [][]mchar {
	words := [][]mchar{nil}
	for _, it := range items {
		if !it.group {
			for k := range words {
				words[k] = append(words[k], it.ch)
			}
			continue
		}
		var parts [][]mchar
		if it.isSeq {
			for _, s := range it.seq {
				var w []mchar
				for j := 0; j < len(s); j++ {
					w = append(w, mchar{c: s[j], k: mLit})
				}
				parts = append(parts, w)
			}
		} else {
			for _, alt := range it.alts {
				parts = append(parts, expandItems(b, alt)...)
			}
		}
		var next [][]mchar
		for _, w := range words {
			for _, part := range parts {
				b.charge(len(w) + len(part))
				nw := make([]mchar, 0, len(w)+len(part))
				nw = append(nw, w...)
				nw = append(nw, part...)
				next = append(next, nw)
			}
		}
		words = next
	}
	return words
}

// expandItemsSeqText is expandItems with each sequence left as the text
// {first..last}, which braceAtoms reads as a digits or a range atom.
func expandItemsSeqText(b *netBudget, items []bitem) [][]mchar {
	words := [][]mchar{nil}
	for _, it := range items {
		if !it.group {
			// A brace or comma outside a list is text.
			ch := it.ch
			if ch.k == mMeta && (ch.c == '{' || ch.c == '}' || ch.c == ',') {
				ch.k = mLit
			}
			for k := range words {
				words[k] = append(words[k], ch)
			}
			continue
		}
		var parts [][]mchar
		if it.isSeq {
			lo, hi := "0", "1" // a sequence too long to list: any digits
			if len(it.seq) > 0 {
				lo, hi = it.seq[0], it.seq[len(it.seq)-1]
			}
			w := []mchar{{c: '{', k: mMeta, st: it.ch.st}}
			for _, t := range []string{lo, "..", hi} {
				for j := 0; j < len(t); j++ {
					w = append(w, mchar{c: t[j], k: mLit})
				}
			}
			w = append(w, mchar{c: '}', k: mMeta})
			parts = append(parts, w)
		} else {
			for _, alt := range it.alts {
				parts = append(parts, expandItemsSeqText(b, alt)...)
			}
		}
		var next [][]mchar
		for _, w := range words {
			for _, part := range parts {
				b.charge(len(w) + len(part))
				nw := make([]mchar, 0, len(w)+len(part))
				nw = append(nw, w...)
				nw = append(nw, part...)
				next = append(next, nw)
			}
		}
		words = next
	}
	return words
}

// buildPatterns returns the patterns of a reading. exactOK allows the
// exact expansion of well formed brace words. cause is causeList when the
// list makes too many words.
func buildPatterns(b *netBudget, ms []mchar, exactOK, fold, flags bool) ([]*netPattern, int) {
	ok, anyBrace := wellFormedBraces(ms)
	if !anyBrace {
		return []*netPattern{newNetPattern(atomsOf(nil, ms, false, flags), fold)}, 0
	}
	if exactOK && ok && !versionDependentSeq(ms) {
		alts, _ := parseBraces(b, ms, 0, false)
		items := alts[0]
		lists, all := braceCounts(items, netMaxList)
		if lists > netMaxList {
			return nil, causeList
		}
		if all <= maxBraceWords {
			var out []*netPattern
			for _, w := range expandItems(b, items) {
				out = append(out, newNetPattern(atomsOf(nil, w, false, flags), fold))
			}
			return out, 0
		}
		// A long list: every word of its lists, with each sequence kept
		// as a digits or a range atom, read without letter case.
		var out []*netPattern
		if lists*len(ms) <= netMaxExpandBytes {
			for _, w := range expandItemsSeqText(b, items) {
				out = append(out, newNetPattern(braceAtoms(w, flags), true))
			}
		} else {
			out = append(out, newNetPattern(braceAtoms(ms, flags), true))
		}
		for _, p := range out {
			p.big = true
		}
		return out, 0
	}
	return []*netPattern{newNetPattern(braceAtoms(ms, flags), fold)}, 0
}

// braceAtoms is the over-approximation of every brace expansion of the
// word: the text before the first { and after the last } is required,
// every piece in between, and each { } and , itself, is optional. A
// sequence in between is an optional range or digits atom.
func braceAtoms(ms []mchar, flags bool) []atom {
	first, last := -1, -1
	for i, m := range ms {
		if m.k == mMeta && m.c == '{' && first < 0 {
			first = i
		}
		if m.k == mMeta && m.c == '}' {
			last = i
		}
	}
	if first < 0 || last < first {
		return atomsOf(nil, ms, false, flags)
	}
	keep := keptBraces(ms, 0)
	out := atomsOf(nil, ms[:first], false, flags)
	i := first
	for i <= last {
		m := ms[i]
		if m.k == mMeta && (m.c == '{' || m.c == '}' || m.c == ',') {
			out = atomsOf(out, ms[i:i+1], !keep[i], flags)
			if m.c == '{' {
				// A sequence body: {x..y}.
				j := i + 1
				for j <= last && !(ms[j].k == mMeta && (ms[j].c == '{' || ms[j].c == '}' || ms[j].c == ',')) {
					j++
				}
				if j <= last && ms[j].c == '}' {
					var sb strings.Builder
					dyn := false
					for _, c := range ms[i+1 : j] {
						if c.k == mDyn {
							dyn = true
						}
						sb.WriteByte(c.c)
					}
					if !dyn {
						if mm := braceIntSeqRe.FindStringSubmatch(sb.String()); mm != nil {
							out = append(out, atom{kind: aDigits, opt: true, startAt: flags && ms[i+1].st})
						} else if mm := braceCharSeqRe.FindStringSubmatch(sb.String()); mm != nil {
							lo, hi := mm[1][0], mm[2][0]
							if lo > hi {
								lo, hi = hi, lo
							}
							out = append(out, atom{kind: aRange, opt: true, lo: lo, hi: hi, startAt: flags && ms[i+1].st})
						}
					}
				}
			}
			i++
			continue
		}
		j := i
		for j <= last && !(ms[j].k == mMeta && (ms[j].c == '{' || ms[j].c == '}' || ms[j].c == ',')) {
			j++
		}
		out = braceUnitAtoms(out, ms[i:j], flags)
		i = j
	}
	return atomsOf(out, ms[last+1:], false, flags)
}

// keptBraces returns the indexes (plus off) of the { and } of each group
// that no reading can make a list or a sequence: one with no comma at its
// own level, no .. and no expansion in it, and no comma or expansion after
// it. Bash keeps such braces as text. (Bash skips a } with no comma before
// it: a{b}c,d} is the list b}c and d, so a comma after the group counts.)
func keptBraces(ms []mchar, off int) map[int]bool {
	keep := map[int]bool{}
	// tail[k]: a comma or an expansion at k or after it.
	tail := make([]bool, len(ms)+1)
	for k := len(ms) - 1; k >= 0; k-- {
		tail[k] = tail[k+1] || ms[k].k == mDyn || ms[k].k == mMeta && ms[k].c == ','
	}
	type open struct {
		at          int
		comma, dyns bool
		parent      int // index in groups of the group around it, or -1
	}
	var stack []open
	// A group in an item of a list is not in every word: the other items
	// drop it. Its braces are kept only when every group around it is
	// kept too, so groups are judged after the whole word is read.
	type group struct {
		open, close, parent int
		self                bool
	}
	var groups []group
	var openIdx []int // index in groups of each open group on the stack
	for k, m := range ms {
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if m.k == mDyn {
				for q := range stack {
					stack[q].dyns = true
				}
			}
			if m.c == '.' && k > 0 && ms[k-1].c == '.' {
				for q := range stack {
					stack[q].dyns = true
				}
			}
			if m.k == mMeta && m.c == ',' {
				top.comma = true
			}
		}
		if m.k != mMeta {
			continue
		}
		switch m.c {
		case '{':
			parent := -1
			if len(openIdx) > 0 {
				parent = openIdx[len(openIdx)-1]
			}
			stack = append(stack, open{at: k, parent: parent})
			groups = append(groups, group{open: k, close: -1, parent: parent})
			openIdx = append(openIdx, len(groups)-1)
		case '}':
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			g := openIdx[len(openIdx)-1]
			openIdx = openIdx[:len(openIdx)-1]
			groups[g].close = k
			groups[g].self = !top.comma && !top.dyns && !tail[k+1]
		}
	}
	// A parent comes before its children in groups.
	kept := make([]bool, len(groups))
	for g := range groups {
		gr := groups[g]
		kept[g] = gr.close >= 0 && gr.self && (gr.parent < 0 || kept[gr.parent])
		if kept[g] {
			keep[gr.open+off] = true
			keep[gr.close+off] = true
		}
	}
	return keep
}

// braceUnitAtoms adds the atoms of the text between two brace marks. Bash
// keeps such text whole: every word of a list holds all of it or none of
// it. An expansion in the text can bring a comma or a brace to a later
// reading, so the text is cut at each expansion, and at each bracket
// expression that holds one, which is read as an expansion. Each piece
// between the cuts is optional as a whole; each cut is an optional
// expansion. A text with .. and an expansion can become a sequence: it
// also gets optional digits and letters.
func braceUnitAtoms(out []atom, ms []mchar, flags bool) []atom {
	hasDyn, dots := false, false
	for k, m := range ms {
		if m.k == mDyn {
			hasDyn = true
		}
		if k > 0 && m.c == '.' && ms[k-1].c == '.' && m.k == mLit && ms[k-1].k == mLit {
			dots = true
		}
	}
	if hasDyn && dots {
		st := flags && len(ms) > 0 && ms[0].st
		out = append(out, atom{kind: aDigits, opt: true, startAt: st})
		out = append(out, atom{kind: aRange, opt: true, lo: 'A', hi: 'z', startAt: st})
		return atomsOf(out, ms, true, flags)
	}
	closes := closingBrackets(ms)
	from := 0
	piece := func(to int) {
		if to <= from {
			return
		}
		n0 := len(out)
		out = atomsOf(out, ms[from:to], false, flags)
		if len(out) > n0 {
			out[n0].skipTo = int32(len(out))
		}
	}
	for k := 0; k < len(ms); k++ {
		end := -1
		if ms[k].k == mDyn {
			end = k
		} else if ms[k].k == mMeta && ms[k].c == '[' && closes[k] > k {
			for q := k + 1; q < closes[k]; q++ {
				if ms[q].k == mDyn {
					end = closes[k]
					break
				}
			}
		}
		if end < 0 {
			continue
		}
		piece(k)
		a := atom{kind: aDyn, opt: true, startAt: flags && ms[k].st}
		for q := k; q <= end; q++ {
			if flags && ms[q].en {
				a.endAt = true
			}
		}
		out = append(out, a)
		k = end
		from = end + 1
	}
	piece(len(ms))
	return out
}

// ---- readings ----

// netDelims are the characters after which a path can start in a run.
const netDelims = "=:,@+%~'\""

func isNetDelim(c byte) bool { return strings.IndexByte(netDelims, c) >= 0 }

func isNetMeta(c byte) bool { return strings.IndexByte("{},*?[]", c) >= 0 }

// netJoinRe matches a backslash, the quotes after it and a newline (or the
// \n escape of $'...'): a line continuation once the quotes are read.
var netJoinRe = regexp.MustCompile(`\\(?:['"]|\$')*(?:\n|\\n)`)

// sigmaText deletes every backslash-newline pair, then every quote and
// backslash.
func sigmaText(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && s[i+1] == '\n' {
			i++
			continue
		}
		if c == '\'' || c == '"' || c == '\\' {
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// decodedTexts is the decoded reading: quotes removed (and a $ before a
// quote), escapes decoded, the other backslashes removed. A NUL gives two
// texts: the text up to it, and the whole text without it.
func decodedTexts(s string) []string {
	out := decodeText(s, false)
	// $'...' also reads \n, \t and the other letter escapes as control
	// characters: a newline there separates commands in a later reading.
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\\' && strings.IndexByte(netLetterEscapes, s[i+1]) >= 0 {
			for _, d := range decodeText(s, true) {
				if !containsString(out, d) {
					out = append(out, d)
				}
			}
			break
		}
	}
	// The exact quote removal of bash, up to three times: one reading per
	// level, so escapes inside and outside $'...' are each read as bash does.
	u := s
	for level := 0; level < 3; level++ {
		var ok bool
		if u, ok = netUnquote(u); !ok {
			break
		}
		for _, d := range append([]string{sigmaText(u)}, decodeText(u, false)...) {
			if !containsString(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// netUnquote removes one level of quotes as bash does: a backslash escapes
// the next character, '...' is literal, "..." keeps the backslash before
// any character but $ ` " \ and newline, and $'...' decodes its escapes. ok
// is false for a quote that does not close.
func netUnquote(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 < len(s) {
				i++
				if s[i] != '\n' {
					b.WriteByte(s[i])
				}
			}
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			j := i + 2
			for j < len(s) && s[j] != '\'' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return "", false
			}
			b.WriteString(netDollarBody(s[i+2 : j]))
			i = j
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
					i++
					if s[i] != '\n' {
						b.WriteByte(s[i])
					}
					continue
				}
				b.WriteByte(s[i])
			}
			if i >= len(s) {
				return "", false
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// netDollarBody decodes the body of $'...': the letter escapes, \\, \',
// \", \? and the numeric escapes. A NUL ends the text, as in bash. Other
// backslashes are kept.
func netDollarBody(body string) string {
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' || i+1 >= len(body) {
			b.WriteByte(c)
			continue
		}
		d := body[i+1]
		if k := strings.IndexByte(netLetterEscapes, d); k >= 0 {
			b.WriteByte(netLetterBytes[k])
			i++
			continue
		}
		if strings.IndexByte("\\'\"?", d) >= 0 {
			b.WriteByte(d)
			i++
			continue
		}
		if d == 'x' || d == 'u' || d == 'U' || (d >= '0' && d <= '7') {
			// The numeric escape: decode it alone and skip its digits.
			base, maxd, off := 8, 3, 1
			switch d {
			case 'x':
				base, maxd, off = 16, 2, 2
			case 'u':
				base, maxd, off = 16, 4, 2
			case 'U':
				base, maxd, off = 16, 8, 2
			}
			j, w := i+off, 0
			for j < len(body) && w < maxd && digitVal(body[j]) >= 0 && digitVal(body[j]) < base {
				j++
				w++
			}
			if w > 0 {
				one := decodeText(body[i:j], false)
				if len(one) > 1 {
					return b.String() + one[0]
				}
				b.WriteString(one[0])
				i = j - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// dollarQuoteClosed reports whether the $'...' text whose quote is at
// s[q] ends with a closing quote.
func dollarQuoteClosed(s string, q int) bool {
	for j := q + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == '\'' {
			return true
		}
	}
	return false
}

// netLetterEscapes are the letters of the $'...' escapes of one control
// character, in the order of netLetterBytes.
const netLetterEscapes = "abefnrtvE"

var netLetterBytes = []byte{7, 8, 27, 12, '\n', '\r', '\t', 11, 27}

// decodeText is one decoded reading; letters decodes the letter escapes.
func decodeText(s string, letters bool) []string {
	var t strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && s[i+1] == '\n' {
			i++
			continue
		}
		if c == '$' && i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"') {
			continue
		}
		if c == '\'' || c == '"' {
			continue
		}
		t.WriteByte(c)
	}
	u := t.String()
	var out strings.Builder
	cut := -1
	for i := 0; i < len(u); {
		c := u[i]
		if c != '\\' || i+1 >= len(u) {
			if c != '\\' {
				out.WriteByte(c)
			}
			i++
			continue
		}
		n, width := 0, 0
		base, maxd, off := 0, 0, 1
		switch d := u[i+1]; {
		case d == 'x':
			base, maxd, off = 16, 2, 2
		case d == 'u':
			base, maxd, off = 16, 4, 2
		case d == 'U':
			base, maxd, off = 16, 8, 2
		case d >= '0' && d <= '7':
			base, maxd, off = 8, 3, 1
		}
		if base == 0 {
			if letters && u[i+1] == '\\' {
				i += 2 // an escaped backslash, removed with the others
				continue
			}
			if k := strings.IndexByte(netLetterEscapes, u[i+1]); letters && k >= 0 {
				out.WriteByte(netLetterBytes[k])
				i += 2
				continue
			}
			i++ // a backslash that starts no escape
			continue
		}
		j := i + off
		for j < len(u) && width < maxd {
			v := digitVal(u[j])
			if v < 0 || v >= base {
				break
			}
			n = n*base + v
			width++
			j++
		}
		if width == 0 {
			i++
			continue
		}
		if n == 0 {
			if cut < 0 {
				cut = out.Len()
			}
		} else if u[i+1] == 'x' || base == 8 {
			out.WriteByte(byte(n))
		} else if n <= utf8.MaxRune {
			out.WriteRune(rune(n))
		}
		i = j
	}
	full := out.String()
	if cut >= 0 {
		return []string{full[:cut], full}
	}
	return []string{full}
}

func digitVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// readingChars turns an unquoted reading into characters. Quotes are gone,
// so every { } , * ? [ ] is meta. $HOME is the home directory, another
// expansion is one dyn character. A ~ at the start of the text or after a
// delimiter is the home directory, and ~user, ~+, ~- is magic. Quote
// characters of raw readings mark a start and an end and are dropped.
func readingChars(s, home string) (ms []mchar, magic bool) {
	startNext := true
	assign := assignPrefixRe.MatchString(s)
	mark := func() {
		if n := len(ms); n > 0 {
			ms[n-1].en = true
		}
		startNext = true
	}
	emit := func(c byte, k uint8) {
		ms = append(ms, mchar{c: c, k: k, st: startNext})
		startNext = false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0:
			emit(0, mDyn)
		case c == '\'' || c == '"':
			mark()
		case c == '~' && startNext:
			// Where bash reads a tilde (the start of a word, a word a
			// brace list makes, after = and : of an assignment), the
			// prefix runs to the next / and ~+ or ~- is magic.
			word := i == 0 || s[i-1] == '{' || s[i-1] == ',' || (assign && (s[i-1] == '=' || s[i-1] == ':'))
			end := i + 1
			for end < len(s) && s[end] != '/' && (word && strings.IndexByte(":,{}='\"", s[end]) < 0 || !word && !isNetDelim(s[end])) {
				end++
			}
			if end > i+1 {
				magic = true
			}
			st := startNext
			for j := 0; j < len(home); j++ {
				ms = append(ms, mchar{c: home[j], k: mLit, st: st && j == 0})
			}
			if home == "" {
				ms = append(ms, mchar{k: mDyn, st: st})
			}
			startNext = false
			i = end - 1
		case c == '$' && i+1 < len(s):
			d := s[i+1]
			switch {
			case d == '{':
				j := strings.IndexByte(s[i+2:], '}')
				name := ""
				end := len(s)
				if j >= 0 {
					name = s[i+2 : i+2+j]
					end = i + 2 + j + 1
				}
				if name == "HOME" && home != "" {
					st := startNext
					for k := 0; k < len(home); k++ {
						ms = append(ms, mchar{c: home[k], k: mLit, st: st && k == 0})
					}
					startNext = false
				} else {
					emit(0, mDyn)
				}
				i = end - 1
			case isNameStart(d):
				j := i + 2
				for j < len(s) && isNameChar(s[j]) {
					j++
				}
				if s[i+1:j] == "HOME" && home != "" {
					st := startNext
					for k := 0; k < len(home); k++ {
						ms = append(ms, mchar{c: home[k], k: mLit, st: st && k == 0})
					}
					startNext = false
				} else {
					emit(0, mDyn)
				}
				i = j - 1
			case isSpecialParam(d):
				emit(0, mDyn)
				i++
			default:
				emit(c, mLit)
			}
		case isNetMeta(c):
			emit(c, mMeta)
			if c == ',' {
				mark()
			}
			if c == '{' {
				startNext = true
			}
		case c == ':' && isURLColon(s, i):
			emit(c, mLit)
		case isNetDelim(c):
			if n := len(ms); n > 0 {
				ms[n-1].en = true
			}
			emit(c, mLit)
			ms[len(ms)-1].en = false
			startNext = true
		default:
			emit(c, mLit)
		}
	}
	if n := len(ms); n > 0 {
		ms[n-1].en = true
	}
	return ms, magic
}

// assignPrefixRe matches a word that starts with NAME=.
var assignPrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// levelOneChars reads one shell word with its quotes: quoted characters
// are literal, unquoted { } , * ? [ ] are meta, expansions are dyn and
// $HOME is the home directory. A ~ at the start is the home directory or
// magic.
func levelOneChars(raw, home string) (ms []mchar, magic bool) {
	lit := func(c byte) { ms = append(ms, mchar{c: c, k: mLit}) }
	dyn := func() { ms = append(ms, mchar{k: mDyn}) }
	homeText := func() {
		if home == "" {
			dyn()
			return
		}
		for k := 0; k < len(home); k++ {
			lit(home[k])
		}
	}
	dollar := func(s string, i int) int {
		next, isExp, literal := consumeDollar(s, i)
		if literal {
			lit('$')
			return i + 1
		}
		if next > len(s) {
			// An unclosed expansion, such as "$(\": it runs to the end.
			next = len(s)
		}
		if next <= i {
			next = i + 1
		}
		if isExp {
			name := s[i+1 : next]
			if name == "HOME" || name == "{HOME}" {
				homeText()
			} else {
				dyn()
			}
		}
		return next
	}
	i := 0
	if strings.HasPrefix(raw, "~") {
		end := 1
		for end < len(raw) && raw[end] != '/' {
			end++
		}
		if end > 1 {
			magic = true
		}
		homeText()
		i = end
	}
	for i < len(raw) {
		c := raw[i]
		switch {
		case c == 0:
			dyn()
			i++
		case c == '\\':
			if i+1 < len(raw) {
				if raw[i+1] != '\n' {
					lit(raw[i+1])
				}
				i += 2
			} else {
				i++
			}
		case c == '$' && i+1 < len(raw) && raw[i+1] == '\'':
			// The body is decoded as bash does, up to a NUL.
			end := skipDollarSingleQuote(raw, i+1)
			body := raw[i+2:]
			if dollarQuoteClosed(raw, i+1) {
				body = raw[i+2 : end-1]
			}
			text := netDollarBody(body)
			for j := 0; j < len(text); j++ {
				lit(text[j])
			}
			i = end
		case c == '$' && i+1 < len(raw) && raw[i+1] == '"':
			// $"..." is a double-quoted text.
			i++
		case c == '\'':
			end := skipSingleQuoteRaw(raw, i)
			for j := i + 1; j < end-1 || (j < end && end == len(raw) && raw[end-1] != '\''); j++ {
				lit(raw[j])
			}
			i = end
		case c == '"':
			end := skipDoubleQuoteRaw(raw, i)
			stop := end - 1
			if end == len(raw) && (end-1 <= i || raw[end-1] != '"') {
				stop = end
			}
			for j := i + 1; j < stop; {
				d := raw[j]
				switch {
				case d == '\\' && j+1 < stop && isDquoteEscape(raw[j+1]):
					if raw[j+1] != '\n' {
						lit(raw[j+1])
					}
					j += 2
				case d == '$':
					j = dollar(raw, j)
				case d == '`':
					j = skipBacktick(raw, j)
					dyn()
				default:
					lit(d)
					j++
				}
			}
			i = end
		case c == '$':
			i = dollar(raw, i)
		case c == '`':
			i = skipBacktick(raw, i)
			dyn()
		case isNetMeta(c):
			ms = append(ms, mchar{c: c, k: mMeta})
			i++
		default:
			lit(c)
			i++
		}
	}
	// Start and end marks at the delimiters and at both ends.
	if len(ms) > 0 {
		ms[0].st = true
		ms[len(ms)-1].en = true
	}
	buf := make([]byte, len(ms))
	for k := range ms {
		buf[k] = ms[k].c
	}
	text := string(buf)
	for k := range ms {
		if ms[k].k == mLit && isNetDelim(ms[k].c) && !(ms[k].c == ':' && isURLColon(text, k)) {
			if k > 0 {
				ms[k-1].en = true
			}
			if k+1 < len(ms) {
				ms[k+1].st = true
			}
		}
	}
	return ms, magic
}

// urlSchemes are the network address schemes whose text after :// starts
// with a host name, not a path on this machine.
var urlSchemes = []string{"https", "http", "ftp", "ssh", "git", "wss", "ws"}

// isURLColon reports whether the colon at i is the one of a network address
// such as https://host/x. A path cannot start after it.
func isURLColon(s string, i int) bool {
	if !strings.HasPrefix(s[i:], "://") || i+3 >= len(s) || s[i+3] == '/' {
		return false
	}
	for _, sc := range urlSchemes {
		if i >= len(sc) && s[i-len(sc):i] == sc {
			j := i - len(sc)
			if j == 0 {
				return true
			}
			b := s[j-1]
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '.' || b == '-') {
				return true
			}
		}
	}
	return false
}

// ---- file system ----

const (
	kMissing uint8 = iota
	kFile
	kDir
	kLink
)

type netEntry struct {
	kind   uint8
	target string
	read   bool // target holds the text of the link
}

type netDir struct {
	names []string
	set   map[string]bool
	lower map[string][]string // names by their lower-case form, made on use
	// short maps the upper-case short 8.3 name of an entry to its name, on
	// Windows. The short names are in names too, so that a pattern can
	// read them, but not in set.
	short map[string]string
	ok    bool
}

// folded returns the names of the directory equal to name without letter
// case.
func (d *netDir) folded(name string) []string {
	if d.lower == nil {
		d.lower = make(map[string][]string, len(d.names))
		for _, n := range d.names {
			k := strings.ToLower(n)
			d.lower[k] = append(d.lower[k], n)
		}
	}
	return d.lower[strings.ToLower(name)]
}

type netFS struct {
	b    *netBudget
	ent  map[string]netEntry
	dirs map[string]*netDir
}

// netRemoteMounts holds the mount points of FUSE and network file systems.
// A call into one of them can wait on another process or host without end,
// so the check does not look into them: a path at or under one is unknown.
var (
	netRemoteOnce   sync.Once
	netRemoteMounts []string
)

// netRemoteTypes are the file system types the check does not look into.
var netRemoteTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"9p": true, "ceph": true, "afs": true, "glusterfs": true, "lustre": true,
	// macOS
	"afpfs": true, "webdav": true, "macfuse": true, "osxfuse": true,
	"fusefs": true, "fuse-t": true,
}

func netRemoteType(t string) bool {
	if t == "fusectl" {
		return false
	}
	return t == "fuse" || t == "fuseblk" || strings.HasPrefix(t, "fuse.") || strings.HasPrefix(t, "macfuse") || strings.HasPrefix(t, "osxfuse") || netRemoteTypes[t]
}

// unescapeMount undoes the octal escapes of a field of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func loadRemoteMounts() {
	for _, m := range remoteMountPoints() {
		netRemoteMounts = append(netRemoteMounts, strings.TrimRight(netInternal(filepath.ToSlash(m)), "/"))
	}
}

// mountinfoRemote returns the mount points of the remote file systems in
// the text of /proc/self/mountinfo.
func mountinfoRemote(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] != "-" {
				continue
			}
			if netRemoteType(fields[i+1]) {
				out = append(out, unescapeMount(fields[4]))
			}
			break
		}
	}
	return out
}

// remote reports whether the path p is at or under a mount point of a
// FUSE or network file system.
func remote(p string) bool {
	netRemoteOnce.Do(loadRemoteMounts)
	if netWindows && (p == "/UNC" || strings.HasPrefix(p, "/UNC/")) {
		return true
	}
	for _, m := range netRemoteMounts {
		if netWindows {
			m = strings.TrimRight(netInternal(m), "/")
		}
		if m == "" || p == m || strings.HasPrefix(p, m+"/") {
			return true
		}
	}
	return false
}

func (f *netFS) lstat(p string) netEntry {
	if remote(p) {
		// Unknown: a directory, so that the walk enters it and finds it
		// unknown.
		return netEntry{kind: kDir, read: true}
	}
	osp, onOS := netOSPath(p)
	if e, ok := f.ent[p]; ok {
		if e.kind == kLink && !e.read {
			e.read = true
			if f.b.lookup() {
				walkLookups.Add(1)
				e.target, _ = sysReadlink(osp)
				e.target = netInternal(filepath.ToSlash(e.target))
			}
			f.ent[p] = e
		}
		return e
	}
	var e netEntry
	e.read = true
	if !onOS {
		// The root of the drives is a directory; another name in it is
		// not there.
		if p == "/" {
			e.kind = kDir
		}
		f.ent[p] = e
		return e
	}
	if f.b.lookup() {
		walkLookups.Add(1)
		if fi, err := sysLstat(osp); err == nil {
			target := ""
			if netWindows && fi.Mode()&os.ModeIrregular != 0 {
				// A junction or another reparse point that names a
				// place: read it as a link.
				target, _ = sysReadlink(osp)
			}
			switch {
			case fi.Mode()&os.ModeSymlink != 0:
				e.kind = kLink
				e.target, _ = sysReadlink(osp)
				e.target = netInternal(filepath.ToSlash(e.target))
			case target != "":
				e.kind = kLink
				e.target = netInternal(filepath.ToSlash(target))
			case fi.IsDir():
				e.kind = kDir
			default:
				e.kind = kFile
			}
		}
	}
	f.ent[p] = e
	return e
}

func (f *netFS) readDir(p string) *netDir {
	if d, ok := f.dirs[p]; ok {
		return d
	}
	d := &netDir{}
	f.dirs[p] = d
	if remote(p) || !f.b.lookup() {
		return d
	}
	walkLookups.Add(1)
	osp, onOS := netOSPath(p)
	if !onOS {
		if p == "/" {
			// The root of the drives lists the drives.
			drives := netDriveNames()
			d.ok = true
			d.set = make(map[string]bool, len(drives))
			for _, n := range drives {
				d.names = append(d.names, n)
				d.set[n] = true
				f.ent[joinDir(p, n)] = netEntry{kind: kDir, read: true}
			}
		}
		return d
	}
	fh, err := sysOpen(osp)
	if err != nil {
		return d
	}
	entries, err := fh.ReadDir(-1)
	fh.Close()
	if err != nil && len(entries) == 0 {
		return d
	}
	f.b.charge(len(entries))
	d.ok = true
	d.set = make(map[string]bool, len(entries))
	if netWindows {
		// The short names are not in the listing of os.ReadDir. A
		// glob does not match them either, so they are not names of
		// the listing: only a name written in full opens one.
		if short := netShortNames(osp); len(short) > 0 {
			f.b.charge(len(short))
			d.short = make(map[string]string, len(short))
			for s, long := range short {
				d.short[strings.ToUpper(s)] = long
			}
		}
	}
	for _, e := range entries {
		n := e.Name()
		d.names = append(d.names, n)
		d.set[n] = true
		child := joinDir(p, n)
		if _, ok := f.ent[child]; ok {
			continue
		}
		t := e.Type()
		switch {
		case t&os.ModeSymlink != 0:
			f.ent[child] = netEntry{kind: kLink}
		case t.IsDir():
			f.ent[child] = netEntry{kind: kDir, read: true}
		case t&os.ModeType == 0 || t.IsRegular():
			f.ent[child] = netEntry{kind: kFile, read: true}
		default:
			// Another type, or a type the directory does not give: ask
			// lstat when it is needed.
			if t&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) != 0 {
				f.ent[child] = netEntry{kind: kFile, read: true}
			}
		}
	}
	return d
}

// netMagicRe matches a path whose meaning depends on the process that
// opens it: the directories and open files of a process.
// netProcRe matches a path under a directory of a process, whether that
// process is there or not.
var netProcRe = regexp.MustCompile(`^/proc/[^/]+/(task/[^/]+/)?(cwd|root|exe|fd|map_files)(/|$)`)

// netProcTaskRe matches the task directory of a process.
var netProcTaskRe = regexp.MustCompile(`^/proc/[^/]+/task$`)

var netMagicRe = regexp.MustCompile(`^/proc/[^/]+/(task/[^/]+/)?(cwd|root|exe|fd/[^/]+|map_files/[^/]+)$|^/dev/fd/[^/]+$|^/dev/(stdin|stdout|stderr)$`)

func parentDir(d string) string {
	if d == "/" {
		return "/"
	}
	i := strings.LastIndexByte(d, '/')
	if i <= 0 {
		return "/"
	}
	return d[:i]
}

// enter returns the place of name in the physical directory dir, with
// links resolved. magic is true when the place goes through a link whose
// target the check cannot know.
func (f *netFS) enter(dir, name string, hops int) (string, uint8, bool) {
	switch name {
	case ".":
		return dir, kDir, false
	case "..":
		return parentDir(dir), kDir, false
	}
	p := joinDir(dir, name)
	if (strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/dev/")) && netMagicRe.MatchString(p) {
		return p, kMissing, true
	}
	if remote(p) {
		return p, kMissing, true
	}
	if _, ok := f.ent[p]; !ok {
		// One listing of the directory answers for all its names.
		if d := f.readDir(dir); d.ok && !d.set[name] {
			if !netWindows {
				return p, kMissing, false
			}
			// Windows also opens a name in another letter case and
			// the short name of a long one: the place is the name the
			// directory lists.
			real := ""
			if long, ok := d.short[strings.ToUpper(name)]; ok {
				real = long
			} else if names := d.folded(name); len(names) > 0 {
				real = names[0]
			} else if strings.Contains(name, "~") {
				if osp, ok := netOSPath(p); ok && f.b.lookup() {
					walkLookups.Add(1)
					if long := netLongName(osp); long != "" && d.set[long] {
						real = long
					}
				}
			}
			if real == "" {
				return p, kMissing, false
			}
			p = joinDir(dir, real)
		}
	}
	e := f.lstat(p)
	if e.kind != kLink {
		return p, e.kind, false
	}
	if strings.HasPrefix(p, "/dev/") {
		return p, kMissing, true
	}
	return f.resolve(dir, e.target, hops+1)
}

// resolve returns the place of the path text under dir.
func (f *netFS) resolve(dir, text string, hops int) (string, uint8, bool) {
	if hops > maxLinkFollows || f.b.over {
		return dir, kMissing, true
	}
	cur, kind := dir, kDir
	if strings.HasPrefix(text, "/") {
		cur = "/"
	}
	parts := strings.Split(text, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if kind != kDir {
			return joinDir(cur, strings.Join(parts[i:], "/")), kMissing, false
		}
		var magic bool
		cur, kind, magic = f.enter(cur, part, hops)
		if magic {
			return cur, kMissing, true
		}
		if kind == kMissing {
			rest := strings.Trim(strings.Join(parts[i+1:], "/"), "/")
			if rest != "" {
				cur = joinDir(cur, rest)
			}
			if netProcRe.MatchString(cur) {
				return cur, kMissing, true
			}
			return cur, kMissing, false
		}
	}
	return cur, kind, false
}

// physical returns the physical form of an absolute path.
func (f *netFS) physical(p string) string {
	p = netInternal(filepath.ToSlash(p))
	if !strings.HasPrefix(p, "/") {
		return p
	}
	r, _, magic := f.resolve("/", p, 0)
	if magic && !remote(r) {
		return filepath.Clean(p)
	}
	// A path that leads onto a remote mount is that place, so that the
	// walk finds it remote and does not look into p again.
	return r
}

// ---- the check ----

type netTarget struct {
	path  string
	dir   bool
	base  string
	names []string
}

type netCtx struct {
	b       *netBudget
	fs      *netFS
	targets []netTarget
	fold    bool
	homes   []string
	homeDyn bool
	// noReads: a command made of reads only is judged like any other
	// (netNames).
	noReads bool
}

func newNetCtx(cmd string, prefixes []string) *netCtx {
	b := &netBudget{}
	c := &netCtx{b: b, fs: &netFS{b: b, ent: map[string]netEntry{}, dirs: map[string]*netDir{}}}
	seen := map[string]bool{}
	for _, raw := range expandPrefixes(prefixes) {
		raw = strings.TrimRight(netInternal(filepath.ToSlash(raw)), "/")
		if raw == "" {
			raw = "/"
		}
		if ignoresCase(raw) {
			c.fold = true
		}
		for _, p := range []string{raw, c.fs.physical(raw)} {
			if seen[p] || !strings.HasPrefix(p, "/") {
				continue
			}
			seen[p] = true
			t := netTarget{path: p, base: filepath.Base(p)}
			if remote(p) {
				// Not looked into; the path itself still counts.
			} else if osp, ok := netOSPath(p); !ok {
				// Not a file of the system.
			} else if fi, err := fsStat(osp); err == nil && fi.IsDir() {
				t.dir = true
				if d := c.fs.readDir(p); d.ok {
					t.names = d.names
				}
			}
			c.targets = append(c.targets, t)
		}
	}
	if strings.Contains(strings.ToLower(cmd), "nocaseglob") {
		c.fold = true
	}
	if home, err := shellHomeDir(); err == nil && home != "" {
		c.homes = append(c.homes, strings.TrimRight(netInternal(home), "/"))
	}
	return c
}

func (c *netCtx) atOrUnder(dir, t string) bool {
	if c.fold {
		dir, t = strings.ToLower(dir), strings.ToLower(t)
	}
	return dir == t || t == "/" || strings.HasPrefix(dir, t+"/")
}

// relBelow returns the text of t below the directory dir, when dir is a
// proper ancestor of t.
func (c *netCtx) relBelow(dir, t string) (string, bool) {
	d, tt := dir, t
	if c.fold {
		d, tt = strings.ToLower(d), strings.ToLower(tt)
	}
	if d == "/" {
		if len(tt) > 1 {
			return t[1:], true
		}
		return "", false
	}
	if len(tt) > len(d) && strings.HasPrefix(tt, d+"/") {
		return t[len(d)+1:], true
	}
	return "", false
}

type netWalkState struct {
	dir   string
	set   []int32
	first bool // the start state at the base, before any character
}

// walk reads the pattern from base (and from / when it can start with a
// slash). names: a reading reaches a protected path. magic: a reading
// goes through a link the check cannot know. In collect mode it returns
// every existing directory a reading names.
//
// A word read as a whole (strict) names a protected path when the base
// itself is in one. A run of text is a mention only when it spells a path
// to one.
func (c *netCtx) walk(p *netPattern, base string, collect, strict bool) (names, magic bool, dirs []string) {
	// On Windows a literal with a colon can hold a drive, which the
	// automaton reads (netDriveStarts).
	if lit, ok := p.literal(); ok && !(netWindows && strings.Contains(lit, ":")) {
		return c.walkLiteral(lit, base, collect, strict)
	}
	init := p.closureOf(p.starts)
	var stack []netWalkState
	if base != "" {
		stack = append(stack, netWalkState{base, init, true})
	}
	if abs := p.step(init, '/', false); len(abs) > 0 {
		stack = append(stack, netWalkState{dir: "/", set: abs})
		if netWindows {
			starts, unc := p.netRootStarts(abs)
			stack = append(stack, starts...)
			if unc {
				magic = true
			}
		}
	}
	if netWindows {
		dirs, sets := p.netDriveStarts(init)
		for i := range dirs {
			stack = append(stack, netWalkState{dir: dirs[i], set: sets[i]})
			// C:name names name in the current directory of drive C:
			// the base when it is on that drive, else a directory the
			// check does not know.
			if p.readsBesides(sets[i], '/') {
				if base != "" && netDriveOf(base) == dirs[i] {
					stack = append(stack, netWalkState{dir: base, set: sets[i]})
				} else {
					magic = true
				}
			}
		}
	}
	seen := map[string]bool{}
	child := func(dir, name string, set []int32) bool {
		path, kind, mg := c.fs.enter(dir, name, 0)
		if mg {
			magic = true
			if collect && remote(path) {
				// As in walkLiteral: a remote place is a base.
				dirs = append(dirs, path)
			}
			return false
		}
		if p.accepts(set) {
			if !collect {
				for _, t := range c.targets {
					if c.atOrUnder(path, t.path) {
						names = true
						return true
					}
					// A word of a long brace list that names a directory
					// above a protected path counts as its name.
					if _, above := c.relBelow(path, t.path); p.big && kind == kDir && above {
						names = true
						return true
					}
				}
			} else if kind == kDir {
				dirs = append(dirs, path)
			}
		}
		if kind == kDir {
			if s := p.step(set, '/', false); len(s) > 0 {
				stack = append(stack, netWalkState{dir: path, set: s})
			}
		}
		return false
	}
	for len(stack) > 0 {
		if c.b.over {
			return
		}
		st := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		key := setKey(st.dir, st.set)
		if seen[key] {
			continue
		}
		seen[key] = true
		c.b.charge(len(st.set) + 1)
		if remote(st.dir) {
			magic = true
			if collect && st.dir != base {
				dirs = append(dirs, st.dir)
			}
			continue
		}
		if (st.dir == "/proc" || netProcTaskRe.MatchString(st.dir)) && p.procMagic(c.b, st.set, st.dir == "/proc") {
			magic = true
			return
		}
		if st.dir == "/" {
			// A directory of a process under /proc, also on a system with
			// no /proc to list (a process can still open such a path
			// through a link or a mount of its own).
			if s := p.step(p.steps(c.b, st.set, "proc"), '/', false); len(s) > 0 && p.procMagic(c.b, s, true) {
				magic = true
				return
			}
		}
		if !collect {
			for _, t := range c.targets {
				if (strict || !st.first) && c.atOrUnder(st.dir, t.path) {
					names = true
					return
				}
				if rel, ok := c.relBelow(st.dir, t.path); ok && p.spells(c.b, st.set, rel) {
					names = true
					return
				}
			}
		} else if p.accepts(st.set) && st.dir != base {
			dirs = append(dirs, st.dir)
		}
		// A slash at the start of a reading names the root, which the
		// state at "/" reads; elsewhere it stays in the directory.
		if s := p.step(st.set, '/', false); len(s) > 0 && !st.first {
			stack = append(stack, netWalkState{dir: st.dir, set: s})
		}
		if name, set, ok := p.fixedName(c.b, st.set); ok {
			if len(name) > netMaxNameLen {
				continue
			}
			if name != "." && name != ".." {
				if d := c.fs.readDir(st.dir); d.ok {
					if p.fold {
						// Every name of the directory equal to it without
						// letter case.
						folded := d.folded(name)
						for _, real := range folded {
							if child(st.dir, real, set) {
								return
							}
						}
						// A short 8.3 name the listing did not give:
						// enter asks the system for its long name.
						if len(folded) == 0 && netWindows && strings.Contains(name, "~") && child(st.dir, name, set) {
							return
						}
						continue
					}
					if !d.set[name] {
						continue
					}
				} else if c.fs.lstat(joinDir(st.dir, name)).kind == kMissing {
					continue
				}
			}
			if child(st.dir, name, set) {
				return
			}
			continue
		}
		d := c.fs.readDir(st.dir)
		cands := append([]string{".", ".."}, d.names...)
		firsts := map[byte][]int32{}
		for _, name := range cands {
			if c.b.over {
				return
			}
			if name == "" {
				continue
			}
			nb, ok := firsts[name[0]]
			if !ok {
				c.b.charge(len(st.set) + 1)
				nb = p.step(st.set, name[0], false)
				firsts[name[0]] = nb
			}
			if len(nb) == 0 {
				continue
			}
			set := p.steps(c.b, nb, name[1:])
			if len(set) == 0 {
				continue
			}
			if child(st.dir, name, set) {
				return
			}
		}
	}
	return
}

// lastPartPossible reports whether the last part of some reading can be
// the name of a protected path, or a name in a protected directory. A
// match made by expansions alone is no evidence.
func (c *netCtx) lastPartPossible(p *netPattern) bool {
	init := map[int32]bool{}
	for _, x := range p.closureOf(p.starts) {
		init[x] = true
	}
	for x := int32(0); x < p.accept; x++ {
		a := &p.atoms[p.atomOf[x]]
		if (a.kind == aLit && a.s[p.offOf[x]] == '/') || a.kind == aDyn {
			for _, y := range p.closureOf([]int32{x}) {
				init[y] = true
			}
			if a.kind == aLit {
				for _, y := range p.closureOf([]int32{x + 1}) {
					init[y] = true
				}
			}
		}
	}
	var names []string
	for _, t := range c.targets {
		names = append(names, t.base)
		names = append(names, t.names...)
	}
	for _, name := range names {
		// A state is a position and whether a character came from text
		// that is not an expansion.
		cur := map[[2]int32]bool{}
		for x := range init {
			cur[[2]int32{x, 0}] = true
		}
		for i := 0; i < len(name) && len(cur) > 0; i++ {
			if !c.b.charge(len(cur) + 1) {
				return true
			}
			nxt := map[[2]int32]bool{}
			for s := range cur {
				x, used := s[0], s[1]
				y := p.next(x, name[i], true)
				if y < 0 {
					continue
				}
				u := used
				if p.atoms[p.atomOf[x]].kind != aDyn {
					u = 1
				}
				for _, z := range p.closureOf([]int32{y}) {
					nxt[[2]int32{z, u}] = true
				}
			}
			cur = nxt
		}
		for s := range cur {
			if s[1] == 1 && p.isEnd[s[0]] {
				return true
			}
		}
	}
	return false
}

// netReading is one reading of a word or run with its patterns.
type netReading struct {
	text  string
	pats  []*netPattern
	cause int
	rel   bool
	dots  bool // a part is "." alone or a ".." component
}

func (c *netCtx) newReading(text string, ms []mchar, magic, exactOK, flags bool) netReading {
	r := netReading{text: text}
	if magic {
		r.cause |= causeMagic
	}
	pats, cause := buildPatterns(c.b, ms, exactOK, c.fold, flags)
	// A name and a .. after it are also read as nothing, as a program that
	// cleans the path text reads them (a{b/../set.json is set.json).
	if lex, ok := lexicalDotDot(ms); ok {
		more, cause2 := buildPatterns(c.b, lex, exactOK, c.fold, flags)
		pats = append(pats, more...)
		cause |= cause2
	}
	r.pats = pats
	r.cause |= cause
	for _, p := range pats {
		if p.hasDyn {
			r.cause |= causeDyn
		}
	}
	r.rel = !(len(ms) > 0 && ms[0].k == mLit && ms[0].c == '/')
	if flags {
		r.rel = true
	}
	for _, piece := range strings.FieldsFunc(text, func(r rune) bool { return r < 128 && isNetDelim(byte(r)) }) {
		if piece == "." {
			r.dots = true
		}
		for _, part := range strings.Split(piece, "/") {
			if part == ".." {
				r.dots = true
			}
		}
	}
	return r
}

// lexicalDotDot returns the characters with each part that a ".." part
// follows removed, together with the "..". ok is false when there is no
// such pair.
func lexicalDotDot(ms []mchar) ([]mchar, bool) {
	isSlash := func(m mchar) bool { return m.k == mLit && m.c == '/' }
	// Parts as ranges between literal slashes.
	type part struct{ from, to int }
	var parts []part
	from := 0
	for i := 0; i <= len(ms); i++ {
		if i == len(ms) || isSlash(ms[i]) {
			parts = append(parts, part{from, i})
			from = i + 1
		}
	}
	dotdot := func(p part) bool {
		return p.to-p.from == 2 && ms[p.from].k == mLit && ms[p.from].c == '.' && ms[p.from+1].k == mLit && ms[p.from+1].c == '.'
	}
	var keep []part
	changed := false
	for _, p := range parts {
		if dotdot(p) && len(keep) > 0 {
			prev := keep[len(keep)-1]
			if prev.to > prev.from && !dotdot(prev) {
				keep = keep[:len(keep)-1]
				changed = true
				continue
			}
		}
		keep = append(keep, p)
	}
	if !changed {
		return nil, false
	}
	var out []mchar
	for i, p := range keep {
		if i > 0 {
			out = append(out, mchar{c: '/', k: mLit})
		}
		out = append(out, ms[p.from:p.to]...)
	}
	if len(out) == 0 {
		return nil, false
	}
	out[0].st = ms[0].st
	return out, true
}

// judge walks the reading under every base. names: a reading reaches a
// protected path. cause: the causes of Unknown.
func (c *netCtx) judge(r netReading, bases []string, uncertain, strict bool) (bool, int) {
	cause := r.cause
	for _, p := range r.pats {
		if r.rel {
			for _, base := range bases {
				if remote(base) {
					cause |= causeRemote
				}
				names, magic, _ := c.walk(p, base, false, strict)
				if names {
					return true, cause
				}
				if magic {
					cause |= causeMagic
				}
			}
		} else {
			names, magic, _ := c.walk(p, "", false, strict)
			if names {
				return true, cause
			}
			if magic {
				cause |= causeMagic
			}
		}
	}
	if r.rel && uncertain {
		cause |= causeBase
	}
	return false, cause
}

// cutRuns cuts the text at blanks, ; | & ( ) < > and backticks, with
// quoting ignored.
func cutRuns(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', ';', '|', '&', '(', ')', '<', '>', '`':
			return true
		}
		return false
	})
}

// runReadings returns the sigma and decoded readings of a run. A run that
// starts with - can hold a path at every offset.
func (c *netCtx) runReadings(run string) []netReading {
	var out []netReading
	exactOK := !strings.ContainsAny(run, "'\"\\")
	texts := []string{sigmaText(run)}
	if strings.ContainsAny(run, "\\$") {
		texts = append(texts, decodedTexts(run)...)
	}
	homes := c.homes
	if len(homes) == 0 {
		homes = []string{""}
	}
	seen := map[string]bool{}
	for ti, text := range texts {
		src := text
		if ti == 0 {
			// Quotes mark a start and an end: read the raw run with the
			// backslashes gone and the quotes kept as marks.
			var sb strings.Builder
			for i := 0; i < len(run); i++ {
				if run[i] == '\\' {
					if i+1 < len(run) && run[i+1] == '\n' {
						i++
					}
					continue
				}
				sb.WriteByte(run[i])
			}
			src = sb.String()
		}
		for _, home := range homes {
			key := src + "\x00" + home
			if seen[key] {
				continue
			}
			seen[key] = true
			c.b.charge(len(src))
			ms, magic := readingChars(src, home)
			if strings.HasPrefix(run, "-") {
				// A path can be glued to an option at any offset, but
				// not inside the host part of a network address.
				buf := make([]byte, len(ms))
				for k := range ms {
					buf[k] = ms[k].c
				}
				chars := string(buf)
				inURL := false
				for k := range ms {
					if !inURL && ms[k].c == ':' && isURLColon(chars, k) {
						inURL = true
					} else if inURL && ms[k].c != ':' && isNetDelim(ms[k].c) {
						inURL = false
					}
					if !inURL {
						ms[k].st = true
					}
				}
			}
			out = append(out, c.newReading(text, ms, magic, exactOK, true))
		}
	}
	return out
}

// netListFits reports whether the brace lists of a word make at most
// netMaxList words, so the net reads the word.
func netListFits(raw string) bool {
	ms, _ := levelOneChars(raw, "")
	ok, any := wellFormedBraces(ms)
	if !ok || !any {
		return false
	}
	b := &netBudget{}
	alts, _ := parseBraces(b, ms, 0, false)
	if len(alts) == 0 {
		return false
	}
	lists, _ := braceCounts(alts[0], netMaxList)
	return lists <= netMaxList && !b.over
}

// netStreamRe matches the standard output and error as a path.
var netStreamRe = streamTargetRe

// redirectOperatorsAreOrdinary reports whether every < and > outside quotes
// is part of an ordinary redirection followed by its operand.
func redirectOperatorsAreOrdinary(cmd string) bool {
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch c {
		case '\\':
			i++
			continue
		case '\'':
			i = skipSingleQuoteRaw(cmd, i) - 1
			continue
		case '"':
			i = skipDoubleQuoteRaw(cmd, i) - 1
			continue
		case '<', '>':
		default:
			continue
		}
		j := i + 1
		if c == '>' {
			if j < len(cmd) && (cmd[j] == '>' || cmd[j] == '|' || cmd[j] == '&') {
				j++
			}
			if j < len(cmd) && (cmd[j] == '!' || cmd[j] == '?') {
				return false
			}
		} else {
			switch {
			case strings.HasPrefix(cmd[j:], "<<"):
				j += 2
			case strings.HasPrefix(cmd[j:], "<-"):
				j += 2
			case j < len(cmd) && (cmd[j] == '<' || cmd[j] == '&' || cmd[j] == '>'):
				j++
			}
		}
		for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
			j++
		}
		if j >= len(cmd) {
			return false
		}
		d := cmd[j]
		if !(isNameChar(d) || d == '\'' || d == '"' || d == '/' || d == '.' || d == '~' || d == '$' || d == '-' || d == '(') {
			return false
		}
		i = j - 1
	}
	return true
}

// netStreamOps are the redirections that leave the standard output and
// error where they are.
var netStreamOps = map[string]bool{
	">": true, ">>": true, "1>": true, "2>": true, "1>>": true, "2>>": true,
	"<": true, "0<": true, "<<": true, "<<-": true, "<<<": true,
	"2>&1": true, "1>&2": true, ">&1": true, ">&2": true, "&>": true, "&>>": true,
}

// streamsSafe reports whether a write to /dev/stdout or /dev/stderr in the
// command writes the standard output or error the command was given.
func (c *netCtx) streamsSafe(toks []shellToken, bases []string, uncertain bool) bool {
	type op struct {
		form    string
		kind    shellTokenKind
		operand *shellToken
	}
	var ops []op
	for i, t := range toks {
		if !isRedirKind(t.kind) {
			continue
		}
		o := op{form: t.fd + t.value, kind: t.kind}
		if i+1 < len(toks) && toks[i+1].kind == tokWord {
			o.operand = &toks[i+1]
			if t.kind == tokRedirDup {
				o.form += toks[i+1].value
			}
		} else if i+1 < len(toks) && toks[i+1].kind == tokSep && toks[i+1].value == "(" {
			o.form = t.value + "("
		}
		ops = append(ops, o)
	}
	all := true
	for _, o := range ops {
		if !netStreamOps[o.form] && o.form != "<(" && o.form != ">(" {
			all = false
		}
	}
	if all {
		return true
	}
	if uncertain {
		return false
	}
	for _, o := range ops {
		if netStreamOps[o.form] || o.form == "<(" || o.form == ">(" {
			continue
		}
		switch {
		case o.kind == tokRedirDup && o.operand != nil && o.operand.value == "-":
			continue // a close
		case o.kind == tokRedirWrite && o.operand != nil && o.form != "<>" && !strings.HasPrefix(o.form, "<"):
			continue // a file: the write check reads it
		case o.kind == tokRedirRead || o.form == "<>" || strings.HasSuffix(o.form, "<>"):
			if o.operand == nil {
				return false
			}
			homes := c.homes
			if len(homes) == 0 {
				homes = []string{""}
			}
			for _, home := range homes {
				ms, magic := levelOneChars(o.operand.raw, home)
				r := c.newReading(o.operand.raw, ms, magic, true, false)
				names, cause := c.judge(r, bases, uncertain, true)
				if names || cause != 0 {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// namesStreamDir reports whether a reading of the text (raw, sigma,
// decoded or joined) holds /dev/ or /proc/, so a stream may be written.
func namesStreamDir(cmd, joined string) bool {
	texts := []string{cmd, sigmaText(cmd), sigmaText(joined)}
	if strings.ContainsAny(cmd, "\\$") {
		texts = append(texts, decodedTexts(cmd)...)
		texts = append(texts, decodedTexts(joined)...)
	}
	for _, t := range texts {
		if strings.Contains(t, "/dev/") || strings.Contains(t, "/proc/") {
			return true
		}
	}
	return false
}

// netIndicatorProgs are programs with a short option that changes the
// directory they run in, and the letters of those options.
var netIndicatorProgs = map[string]string{
	"env": "C", "git": "C", "make": "C", "gmake": "C", "bmake": "C",
	"tar": "C", "gtar": "C", "bsdtar": "C", "ninja": "C", "cmake": "C",
	"meson": "C", "patch": "Cd", "go": "C", "cargo": "C", "pnpm": "C",
	"sudo": "D", "nsenter": "w", "docker": "w", "podman": "w",
	"unzip": "d",
}

// netRootProgs are programs whose first operand is a directory the rest
// of the command runs in.
var netRootProgs = map[string]bool{"chroot": true}

// netGroupPaths returns, for each token, the path of the ( ) groups it is
// in: "/" outside every group, "/1/" in the first group, "/1/2/" in a
// group in it. A group runs in a child shell: a directory change in it
// does not move the shell outside it.
func netGroupPaths(toks []shellToken) []string {
	out := make([]string, len(toks))
	stack := []string{"/"}
	n := 0
	for i, t := range toks {
		if t.kind == tokSep && t.value == ")" && len(stack) > 1 {
			stack = stack[:len(stack)-1]
		}
		out[i] = stack[len(stack)-1]
		if t.kind == tokSep && t.value == "(" {
			n++
			stack = append(stack, stack[len(stack)-1]+strconv.Itoa(n)+"/")
		}
	}
	return out
}

// netSegments splits the tokens as splitShellSegments does and returns the
// group path of each segment.
func netSegments(toks []shellToken) (segs [][]shellToken, paths []string) {
	gp := netGroupPaths(toks)
	var cur []shellToken
	curPath := ""
	for i, t := range toks {
		if t.kind == tokSep {
			if len(cur) > 0 {
				segs = append(segs, cur)
				paths = append(paths, curPath)
				cur = nil
			}
			continue
		}
		if len(cur) == 0 {
			curPath = gp[i]
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
		paths = append(paths, curPath)
	}
	return segs, paths
}

// netGlob is an operand of a directory change that is a pattern.
type netGlob struct {
	text  string
	shell bool   // a change of the shell (cd), not of one program
	path  string // the group path of the change
}

// netDirInfo is what dirIndicators reads.
type netDirInfo struct {
	ops   []string  // the operands of the changes
	globs []netGlob // the operands that are patterns
	// bareCd: the group paths of a cd with no operand, which goes to the
	// home directory.
	bareCd []string
	// uncertain: a change, of the shell or of one program, the check
	// cannot resolve.
	uncertain bool
	// shellUnc: the group paths of the changes of the shell (cd, pushd,
	// popd, chdir, CDPATH) the check cannot resolve.
	shellUnc []string
}

// dirIndicators reads the directory changes of the command: the changes
// of the shell (cd, pushd, popd, chdir and CDPATH) and the options and
// operands that make one program run in another directory.
func dirIndicators(toks []shellToken) netDirInfo {
	var d netDirInfo
	classify := func(marked string, shell bool, path string) {
		if marked != "" {
			d.ops = append(d.ops, marked)
		}
		unc := false
		switch {
		case strings.ContainsRune(marked, rune(shellUnresolvedMark)) || strings.ContainsAny(marked, "$`"):
			unc = true
		case marked == "-" || marked == "":
			unc = true
		case strings.HasPrefix(marked, "~") && marked != "~" && !strings.HasPrefix(marked, "~/"):
			unc = true
		case strings.ContainsAny(marked, "*?["):
			d.globs = append(d.globs, netGlob{text: marked, shell: shell, path: path})
		}
		if unc {
			d.uncertain = true
			if shell {
				d.shellUnc = append(d.shellUnc, path)
			}
		}
	}
	shellUnc := func(path string) {
		d.uncertain = true
		d.shellUnc = append(d.shellUnc, path)
	}
	segs, paths := netSegments(toks)
	for si, seg := range segs {
		path := paths[si]
		words := commandWords(seg)
		firstOp := len(words) // the index of the first word after words[0] that is not an option
		for k := 1; k < len(words); k++ {
			if !strings.HasPrefix(words[k].value, "-") {
				firstOp = k
				break
			}
		}
		for i, w := range words {
			v := w.value
			if strings.Contains(w.raw, "CDPATH") || strings.Contains(v, "CDPATH") {
				// CDPATH moves every later cd: read it as a change of the
				// outer shell.
				shellUnc("/")
			}
			if v == "-execdir" || v == "-okdir" {
				d.uncertain = true
			}
			switch filepath.Base(v) {
			case "cd", "pushd", "chdir":
				var operand *shellToken
				for k := i + 1; k < len(words); k++ {
					if words[k].value == "--" {
						if k+1 < len(words) {
							operand = &words[k+1]
						}
						break
					}
					if strings.HasPrefix(words[k].value, "-") && words[k].value != "-" && !words[k].unresolved {
						continue
					}
					operand = &words[k]
					break
				}
				if operand == nil {
					d.bareCd = append(d.bareCd, path)
				} else if operand.unresolved {
					shellUnc(path)
				} else {
					classify(operand.marked, true, path)
				}
			case "popd":
				shellUnc(path)
			}
			if i > 0 && !strings.HasPrefix(v, "-") {
				// The first operand of chroot; any operand of a program
				// the check cannot know.
				first := firstOp == i
				if words[0].unresolved || first && netRootProgs[filepath.Base(words[0].value)] {
					classify(w.marked, false, path)
				}
			}
			if strings.HasPrefix(v, "--") {
				name := strings.ToLower(w.marked[2:])
				if strings.HasPrefix(name, "ch") || strings.HasPrefix(name, "dir") || strings.HasPrefix(name, "cwd") || strings.HasPrefix(name, "work") || strings.HasPrefix(name, "cd") || strings.HasPrefix(name, "wd") {
					if eq := strings.IndexByte(w.marked, '='); eq >= 0 {
						classify(w.marked[eq+1:], false, path)
					} else if i+1 < len(words) {
						classify(words[i+1].marked, false, path)
					}
				}
				continue
			}
			if len(v) > 1 && v[0] == '-' {
				letters := ""
				if len(words) > 0 && words[0].unresolved {
					// A program the check cannot know: any letter.
					letters = w.marked[1:]
				}
				for _, prev := range words[:i] {
					letters += netIndicatorProgs[filepath.Base(prev.value)]
				}
				k := -1
				for q := 1; q < len(w.marked); q++ {
					if strings.IndexByte(letters, w.marked[q]) >= 0 {
						k = q
						break
					}
				}
				if k <= 0 {
					continue
				}
				if rest := w.marked[k+1:]; rest != "" {
					classify(rest, false, path)
				} else if i+1 < len(words) {
					classify(words[i+1].marked, false, path)
				} else {
					d.uncertain = true
				}
			}
		}
	}
	return d
}

// homeAssignments returns the literal values of HOME= in the command, and
// whether one is not literal.
func homeAssignments(toks []shellToken) (vals []string, dyn bool) {
	for _, t := range toks {
		if t.kind == tokWord && (t.value == "HOME" || strings.HasPrefix(t.value, "HOME+=")) {
			// printf -v HOME, read HOME, HOME+=...: a value the check
			// does not read.
			dyn = true
			continue
		}
		if t.kind != tokWord || !strings.HasPrefix(t.value, "HOME=") {
			continue
		}
		if t.unresolved {
			dyn = true
			continue
		}
		if v := strings.TrimRight(netInternal(t.value[len("HOME="):]), "/"); strings.HasPrefix(v, "/") {
			vals = append(vals, v)
		}
	}
	return vals, dyn
}

// netWriteTarget is a word the command writes: a redirect target or an
// operand of a program that writes.
type netWriteTarget struct {
	tok      shellToken
	raw      string
	redirect bool
	path     string // a redirect: the group path of the shell that opens it
}

func netWriteTargets(toks []shellToken) []netWriteTarget {
	var out []netWriteTarget
	gp := netGroupPaths(toks)
	for i, t := range toks {
		if t.kind != tokRedirWrite && t.kind != tokRedirDup {
			continue
		}
		if i+1 >= len(toks) || toks[i+1].kind != tokWord {
			continue
		}
		op := toks[i+1]
		if t.kind == tokRedirDup && isBareFd(op.value) {
			continue
		}
		out = append(out, netWriteTarget{tok: op, raw: op.raw, redirect: true, path: gp[i]})
	}
	for _, seg := range splitShellSegments(toks) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) < 2 || words[0].unresolved {
			continue
		}
		prog := filepath.Base(words[0].value)
		if !isMutatingProg(prog, wordValues(words)) {
			continue
		}
		ddash := false
		for _, w := range words[1:] {
			if !ddash && w.value == "--" && !w.unresolved {
				ddash = true
				continue
			}
			if !ddash && !w.unresolved && len(w.value) > 1 && w.value[0] == '-' {
				// An option: only a path glued to it is a target.
				if s := stripPathOption(w.value); s != w.value && s != "" {
					if strings.HasSuffix(w.raw, s) {
						out = append(out, netWriteTarget{tok: w, raw: w.raw[len(w.raw)-len(s):]})
					} else {
						out = append(out, netWriteTarget{tok: w, raw: w.raw})
					}
				}
				continue
			}
			out = append(out, netWriteTarget{tok: w, raw: w.raw})
		}
	}
	return out
}

// netShellTexts returns the texts that shells in the command run, and
// whether one of them starts with a program name the check cannot know.
func netShellTexts(toks []shellToken) (texts []string, unknownProg bool) {
	addText := func(text string) {
		texts = append(texts, text)
		for _, s := range splitShellSegments(tokenizeShell(text)) {
			if w := stripCommandPrefix(commandWords(s)); len(w) > 0 && w[0].unresolved {
				unknownProg = true
			}
		}
	}
	stdinShell := false
	for _, seg := range splitShellSegments(toks) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) == 0 || words[0].unresolved {
			continue
		}
		switch filepath.Base(words[0].value) {
		case "eval":
			// eval runs its words joined with blanks.
			if len(words) > 1 {
				var parts []string
				for _, w := range words[1:] {
					parts = append(parts, w.marked)
				}
				// An eval text whose words the check cannot read is the
				// old check's case: here only its writes are read.
				texts = append(texts, strings.Join(parts, " "))
			}
			continue
		case "trap":
			// trap runs its first operand later.
			for _, w := range words[1:] {
				texts = append(texts, w.marked)
			}
			continue
		}
		if !shellInterpreters[filepath.Base(words[0].value)] {
			continue
		}
		call := parseShellCall(filepath.Base(words[0].value), words[1:])
		if call.stdin || !call.known {
			stdinShell = true
		}
		if len(words) < 2 {
			continue
		}
		for _, arg := range call.writeCheckTexts() {
			addText(arg.marked)
		}
		for _, arg := range words[1:] {
			if strings.ContainsAny(arg.value, " \t\n;|&<>()`") || strings.Contains(arg.raw, "$(") || strings.Contains(arg.raw, "`") {
				texts = append(texts, arg.marked)
			}
		}
	}
	if stdinShell {
		// A shell that reads its commands from the standard input can run
		// any word of the command (echo 'rm f' | bash, bash <<< 'rm f'). A
		// word with no blank or operator in it is one program name, which
		// writes no file the check reads.
		for _, t := range toks {
			if t.kind == tokWord && strings.ContainsAny(t.marked, " \t\n;|&<>()`") {
				texts = append(texts, t.marked)
			}
		}
	}
	return texts, unknownProg
}

// netCheck is the check of one top-level command text. work are the
// directories the tool call says it runs in.
func netCheck(cmd string, prefixes, work []string) (bool, string) {
	// Native Windows shells keep backslashes as path separators: the text
	// is also read with them as slashes (shellTouchesProtectedRec).
	if netWindows && strings.Contains(cmd, `\`) {
		for _, text := range []string{cmd, decodeWindowsShellEscapes(cmd)} {
			if hit, why := netCheckText(strings.ReplaceAll(text, `\`, "/"), prefixes, work); hit {
				return true, why
			}
		}
	}
	return netCheckText(cmd, prefixes, work)
}

func netCheckText(cmd string, prefixes, work []string) (bool, string) {
	c := newNetCtx(cmd, prefixes)
	if len(c.targets) == 0 {
		return false, ""
	}
	hit, why := c.check(cmd, 0, work, false)
	if !hit && c.b.over {
		return true, "a command too large to check"
	}
	return hit, why
}

const netOverReason = "a command too large to check"

// netNames returns a reason when the command text names a protected path,
// whatever the programs of the command do, or "". inherited are the
// directories the text is also read under.
func netNames(cmd string, prefixes, inherited []string) string {
	if netWindows && strings.Contains(cmd, `\`) {
		for _, text := range []string{cmd, decodeWindowsShellEscapes(cmd)} {
			if why := netNamesText(strings.ReplaceAll(text, `\`, "/"), prefixes, inherited); why != "" {
				return why
			}
		}
	}
	return netNamesText(cmd, prefixes, inherited)
}

func netNamesText(cmd string, prefixes, inherited []string) string {
	c := newNetCtx(cmd, prefixes)
	if len(c.targets) == 0 {
		return ""
	}
	c.noReads = true
	hit, why := c.check(cmd, 0, inherited, false)
	if !hit && c.b.over {
		return netOverReason
	}
	if hit && why == "" {
		why = shortRaw(cmd)
	}
	return why
}

// unreadWord is the name check of one command under the bases. It returns
// a reason when the text names a protected path, or "". It is kept for the
// tests of the long brace-list rule; the net reads every word.
func unreadWord(cmd string, _ []shellToken, bases, prefixes []string) string {
	return netNames(cmd, prefixes, bases)
}

// netDirsReason is the reason for a command that names more directories at
// or above a protected path than the check reads.
const netDirsReason = "a command with more directories than the check reads"

// tooManyDirs reports whether more than maxProtectedBases different
// readings name an existing directory at or above a protected path.
func (c *netCtx) tooManyDirs(readings []netReading, bases []string) bool {
	texts := map[string]bool{}
	for _, r := range readings {
		texts[r.text] = true
	}
	if len(texts) <= maxProtectedBases {
		return false
	}
	above := func(d string) bool {
		for _, t := range c.targets {
			if c.atOrUnder(t.path, d) {
				return true
			}
		}
		return false
	}
	counted := map[string]bool{}
	for _, r := range readings {
		if counted[r.text] {
			continue
		}
		froms := []string{""}
		if r.rel {
			froms = bases
		}
	pats:
		for _, p := range r.pats {
			for _, from := range froms {
				_, _, dirs := c.walk(p, from, true, true)
				if c.b.over {
					return true
				}
				for _, d := range dirs {
					if above(d) {
						counted[r.text] = true
						break pats
					}
				}
			}
		}
		if len(counted) > maxProtectedBases {
			return true
		}
	}
	return false
}

// check runs the rules on one text. inherited are the directories of the
// text around it, and uncertain whether one of its changes is not known.
func (c *netCtx) check(cmd string, depth int, inherited []string, inhUncertain bool) (bool, string) {
	if depth > maxShellSubstDepth {
		return true, shortRaw(cmd)
	}
	toks := tokenizeShell(cmd)
	sigToks := tokenizeShell(sigmaText(cmd))
	// joined: the text with each backslash that quotes and a newline
	// follow joined to the next line, as a later reading of the text does
	// ('a\'"<newline>"'b' read again is ab).
	joined := netJoinRe.ReplaceAllString(cmd, "")
	var joinToks []shellToken
	if joined != cmd {
		joinToks = tokenizeShell(sigmaText(joined))
	}

	// The decoded texts of the command ($'...' escapes and the quote
	// removal of later readings), each read again as a command: a blank or
	// a newline in one separates words and commands there.
	var decTexts []string
	var decToks [][]shellToken
	if strings.ContainsAny(cmd, "\\$") {
		sig := sigmaText(cmd)
		for _, d := range decodedTexts(cmd) {
			if d == cmd || d == joined || d == sig || containsString(decTexts, d) {
				continue
			}
			if !c.b.charge(len(d)) {
				return true, netOverReason
			}
			decTexts = append(decTexts, d)
			decToks = append(decToks, tokenizeShell(d))
		}
	}

	// HOME values and directory changes.
	allToks := append(append(append([]shellToken{}, toks...), sigToks...), joinToks...)
	for _, dt := range decToks {
		allToks = append(allToks, dt...)
	}
	vals, homeDyn := homeAssignments(allToks)
	saved := c.homes
	defer func() { c.homes = saved }()
	for _, v := range vals {
		if !containsString(c.homes, v) {
			c.homes = append(c.homes, v)
		}
	}
	if homeDyn && !containsString(c.homes, "") {
		// A HOME the check cannot read: ~ and $HOME are read as any text.
		c.homes = append(append([]string{}, c.homes...), "")
	}
	// The directory changes, read from each token stream. A redirect is
	// opened by the shell of its group: a change of the shell in that
	// group or in a group around it moves it (shellMoves).
	streams := [][]shellToken{toks, sigToks}
	if joinToks != nil {
		streams = append(streams, joinToks)
	}
	streams = append(streams, decToks...)
	var infos []netDirInfo
	var ops []string
	var globs []netGlob
	bareCd := false
	uncertain := inhUncertain
	for _, st := range streams {
		d := dirIndicators(st)
		if homeDyn {
			d.shellUnc = append(d.shellUnc, d.bareCd...)
			if len(d.bareCd) > 0 {
				d.uncertain = true
			}
		}
		infos = append(infos, d)
		ops = append(ops, d.ops...)
		globs = append(globs, d.globs...)
		bareCd = bareCd || len(d.bareCd) > 0
		uncertain = uncertain || d.uncertain
	}
	redirs := make([][]netWriteTarget, len(streams))
	for i, st := range streams {
		for _, w := range netWriteTargets(st) {
			if w.redirect {
				redirs[i] = append(redirs[i], w)
			}
		}
	}
	// globShell: a cd to a pattern that names no directory, by group path.
	var globShell []string
	shellMoves := func(k int) bool {
		if inhUncertain || len(globShell) > 0 && containsString(globShell, "/") {
			return true
		}
		for i, d := range infos {
			unc := d.shellUnc
			if i == 0 {
				unc = append(append([]string{}, unc...), globShell...)
			}
			if len(unc) == 0 {
				continue
			}
			if len(redirs[i]) != len(redirs[0]) || k >= len(redirs[i]) {
				return true
			}
			for _, u := range unc {
				if strings.HasPrefix(redirs[i][k].path, u) {
					return true
				}
			}
		}
		return false
	}

	// Rule 1 readings: every run of the raw text (and of the text with the
	// backslash-newline pairs gone) and every word read with its quotes.
	var readings []netReading
	texts := []string{cmd}
	if strings.Contains(cmd, "\\\n") {
		texts = append(texts, strings.ReplaceAll(cmd, "\\\n", ""))
	}
	if joined != cmd && !containsString(texts, joined) {
		texts = append(texts, joined)
	}
	texts = append(texts, decTexts...)
	seenRun := map[string]bool{}
	for _, text := range texts {
		for _, run := range cutRuns(text) {
			if seenRun[run] || netStreamRe.MatchString(run) {
				continue
			}
			seenRun[run] = true
			if !c.b.charge(len(run)) {
				return true, netOverReason
			}
			readings = append(readings, c.runReadings(run)...)
		}
	}
	home := ""
	if len(c.homes) > 0 {
		home = c.homes[0]
	}
	for _, t := range toks {
		if t.kind != tokWord || netStreamRe.MatchString(t.value) {
			continue
		}
		if !c.b.charge(len(t.raw)) {
			return true, netOverReason
		}
		ms, magic := levelOneChars(t.raw, home)
		readings = append(readings, c.newReading(t.raw, ms, magic, true, true))
	}

	// Bases: every existing directory a reading names, under the bases
	// found so far.
	var bases []string
	baseSet := map[string]bool{}
	addBase := func(d string) bool {
		if d == "" || baseSet[d] {
			return false
		}
		baseSet[d] = true
		bases = append(bases, d)
		return true
	}
	for _, d := range inherited {
		addBase(c.fs.physical(d))
	}
	if wd, err := fsGetwd(); err == nil {
		addBase(c.fs.physical(wd))
	}
	if strings.ContainsAny(cmd, "~") || strings.Contains(cmd, "$HOME") || strings.Contains(cmd, "${HOME}") || bareCd {
		for _, h := range c.homes {
			addBase(c.fs.physical(h))
		}
	} else {
		for _, h := range vals {
			addBase(c.fs.physical(h))
		}
	}
	// Any word may be a directory a program changes to: every directory a
	// word with a name in it can name under the first bases is a base too.
	first := len(bases)
	for i := 0; i < first; i++ {
		for _, r := range readings {
			for _, p := range r.pats {
				if !p.hasName() {
					continue
				}
				_, _, dirs := c.walk(p, bases[i], true, true)
				for _, d := range dirs {
					addBase(d)
				}
				if c.b.over {
					return true, netOverReason
				}
			}
		}
	}
	// The operands of the directory changes, one after another.
	var opReadings []netReading
	for _, op := range ops {
		ms, magic := readingChars(op, home)
		opReadings = append(opReadings, c.newReading(op, ms, magic, true, false))
	}
	// An operand that names both .. and any name, such as *, takes the
	// bases up and down the whole file system, which is more than the
	// budget reads. Deny it as too large before the walk.
	for _, r := range opReadings {
		for _, p := range r.pats {
			if p.roamsTree(c.b) {
				c.b.over = true
				return true, netOverReason
			}
		}
	}
	for i := 0; i < len(bases); i++ {
		for _, r := range opReadings {
			for _, p := range r.pats {
				_, _, dirs := c.walk(p, bases[i], true, true)
				for _, d := range dirs {
					addBase(d)
				}
				if c.b.over {
					return true, netOverReason
				}
			}
		}
	}
	for _, g := range globs {
		ms, _ := readingChars(g.text, home)
		found := false
		for _, p := range c.newReading(g.text, ms, false, true, false).pats {
			for _, base := range bases {
				if _, _, dirs := c.walk(p, base, true, true); len(dirs) > 0 {
					found = true
				}
			}
		}
		if !found {
			uncertain = true
			if g.shell {
				// The group path is of the stream the glob came from;
				// read it as a change of the outer shell.
				globShell = append(globShell, "/")
			}
		}
	}
	if c.b.over {
		return true, netOverReason
	}

	// Rule 2: redirect targets and operands of programs that write, read
	// with their quotes.
	rk := -1
	for _, w := range netWriteTargets(toks) {
		unc := uncertain
		if w.redirect {
			rk++
			unc = shellMoves(rk)
		}
		if netStreamRe.MatchString(w.tok.value) {
			continue
		}
		// One reading per home: a ~ or $HOME is each home the command
		// can have.
		hs := homesOr(c.homes)
		if !strings.ContainsAny(w.raw, "~$") {
			hs = hs[:1]
		}
		deny := false
		denyCause := 0
		for _, h := range hs {
			ms, magic := levelOneChars(w.raw, h)
			r := c.newReading(w.raw, ms, magic, true, false)
			names, cause := c.judge(r, bases, unc, true)
			if c.b.over {
				return true, netOverReason
			}
			switch {
			case names:
				deny = true
			case cause == 0 || c.noReads:
			case w.redirect:
				deny = true
			case cause == causeBase && !r.dots && !c.anyLastPart(r):
			default:
				deny = true
			}
			if deny {
				denyCause = cause
				if names {
					denyCause = 0
				}
				break
			}
		}
		if deny {
			return true, unknownReason(w.tok.raw, denyCause)
		}
	}

	// Streams.
	if !c.noReads && namesStreamDir(cmd, joined) {
		if !c.streamsSafe(toks, bases, uncertain) {
			return true, "a write to the standard output or error after a redirection the check cannot read"
		}
	}

	// Texts the command runs.
	shellTexts, unknownProg := netShellTexts(toks)
	if unknownProg && !c.noReads {
		return true, "a shell command whose program the check cannot know"
	}
	for _, text := range append(shellTexts, extractCommandSubsts(cmd)...) {
		if hit, why := c.check(text, depth+1, bases, uncertain); hit {
			return true, why
		}
	}
	if c.b.over {
		return true, netOverReason
	}

	// More directories at or above a protected path than the check reads.
	if c.tooManyDirs(readings, bases) {
		if c.b.over {
			return true, netOverReason
		}
		return true, netDirsReason
	}

	// A command made of reads only writes nothing.
	if !c.noReads && shellOnlyReads(cmd, 0) && redirectOperatorsAreOrdinary(cmd) {
		return false, ""
	}

	// The shell option nocaseglob makes a pattern match without letter case.
	if strings.Contains(strings.ToLower(cmd), "nocaseglob") {
		return true, "nocaseglob"
	}

	// Rule 1: a reading of any run or word.
	for _, r := range readings {
		names, cause := c.judge(r, bases, uncertain, false)
		if c.b.over {
			return true, netOverReason
		}
		if names {
			return true, shortRaw(r.text)
		}
		if cause&(causeMagic|causeList) != 0 {
			return true, unknownReason(r.text, cause)
		}
		if cause&causeBase != 0 && r.dots {
			return true, unknownReason(r.text, cause)
		}
		if cause&(causeDyn|causeBase) != 0 && c.anyLastPart(r) {
			return true, unknownReason(r.text, cause)
		}
	}
	return false, ""
}

// homesOr returns the homes, or one empty home when there is none.
func homesOr(homes []string) []string {
	if len(homes) == 0 {
		return []string{""}
	}
	return homes
}

func (c *netCtx) anyLastPart(r netReading) bool {
	for _, p := range r.pats {
		if c.lastPartPossible(p) {
			return true
		}
	}
	return false
}
