package engine

// Property tests of the check of shell text (protect_net.go): the sigma
// reading is unchanged by quote removal, and the brace atoms hold every
// word real bash makes from a brace list. FuzzNetCheck runs the whole check
// on random commands.

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bashUnquote removes one level of quotes from a text as bash does before
// eval or sh -c reads it again. ok is false for a quote that does not
// close.
func bashUnquote(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				b.WriteByte(c)
				continue
			}
			i++
			if s[i] != '\n' {
				b.WriteByte(s[i])
			}
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			i += 2
			for ; i < len(s) && s[i] != '\''; i++ {
				if s[i] != '\\' || i+1 >= len(s) {
					b.WriteByte(s[i])
					continue
				}
				i++
				switch k := strings.IndexByte("abefnrtv", s[i]); {
				case k >= 0:
					b.WriteByte([]byte{7, 8, 27, 12, '\n', '\r', '\t', 11}[k])
				case strings.IndexByte("\\'\"?", s[i]) >= 0:
					b.WriteByte(s[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(s[i])
				}
			}
			if i >= len(s) {
				return "", false
			}
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

// Quote removal applied any number of times, then sigma, gives one of the
// texts the check reads: the sigma or the decoded text of the raw text or
// of its joined text (netJoinRe). The texts are compared without $: the
// readings keep or drop a $ next to a quote where bash may not, and a $
// only adds or removes a dollar sign, never a part of a protected name.
func TestNetSigmaInvariance(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "b", "/", "'", "\"", "\\", "\n", "$'", " ", "\\n", "."}
	tried := 0
	for n := 0; n < 200000 && tried < 20000; n++ {
		var sb strings.Builder
		for k := rng.Intn(12) + 1; k > 0; k-- {
			sb.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		raw := sb.String()
		u, ok := bashUnquote(raw)
		if !ok {
			continue
		}
		tried++
		joined := netJoinRe.ReplaceAllString(raw, "")
		noDollar := func(s string) string { return strings.ReplaceAll(s, "$", "") }
		read := map[string]bool{noDollar(sigmaText(raw)): true, noDollar(sigmaText(joined)): true}
		for _, d := range append(decodedTexts(raw), decodedTexts(joined)...) {
			read[noDollar(d)] = true
		}
		for level := 1; level <= 3 && ok; level++ {
			if !read[noDollar(sigmaText(u))] {
				t.Fatalf("raw %q: level %d gives sigma %q, the check reads %q", raw, level, sigmaText(u), keys(read))
			}
			u, ok = bashUnquote(u)
		}
	}
	if tried < 1000 {
		t.Fatalf("only %d texts tried", tried)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// netAccepts reports whether one of the patterns matches the whole text.
func netAccepts(pats []*netPattern, text string) bool {
	for _, p := range pats {
		b := &netBudget{}
		if p.accepts(p.steps(b, p.closureOf(p.starts), text)) {
			return true
		}
	}
	return false
}

// randomBraceWord returns a word made of letters, commas, braces, dots,
// slashes and sequences, with no character that bash reads as a glob, a
// blank or a quote.
func randomBraceWord(rng *rand.Rand) string {
	parts := []string{"a", "b", "c", ".", "/", ",", "{", "}", "{a,b}", "{1..3}", "{x..z}", "{,}", "{}", "\\,", "\\{", "\\}"}
	var sb strings.Builder
	for k := rng.Intn(10) + 1; k > 0; k-- {
		sb.WriteString(parts[rng.Intn(len(parts))])
	}
	return sb.String()
}

// Every word real bash makes from a random brace word is matched by the
// brace atoms of the word, and by the patterns of the exact reading.
func TestNetBraceSoundnessAgainstBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	rng := rand.New(rand.NewSource(2))
	const n = 400
	words := make([]string, n)
	var script strings.Builder
	for i := range words {
		words[i] = randomBraceWord(rng)
		script.WriteString("printf '%s\\n' " + words[i] + "; echo '\x01'\n")
	}
	// The script goes in on standard input: on Windows the runtime of Git
	// bash parses a -c argument again and changes its backslashes and
	// quotes, so bash would run other words.
	run := exec.Command(bash, "--norc", "--noprofile", "-s")
	run.Stdin = strings.NewReader(script.String())
	out, err := run.Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	groups := strings.Split(strings.TrimSuffix(string(out), "\x01\n"), "\x01\n")
	if len(groups) != n {
		t.Fatalf("bash gave %d groups, want %d", len(groups), n)
	}
	for i, g := range groups {
		ms, _ := levelOneChars(words[i], "")
		atoms := []*netPattern{newNetPattern(braceAtoms(ms, false), false)}
		exact, _ := buildPatterns(&netBudget{}, ms, true, false, false)
		for _, w := range strings.Split(strings.TrimSuffix(g, "\n"), "\n") {
			if !netAccepts(atoms, w) {
				t.Errorf("word %q: bash makes %q, the brace atoms do not match it", words[i], w)
			}
			if !netAccepts(exact, w) {
				t.Errorf("word %q: bash makes %q, the exact patterns do not match it", words[i], w)
			}
		}
	}
}

// Long sequences (netMaxList words and more) and sequences at the int64
// limits: every word bash makes is matched. bash keeps the text of a
// sequence it does not make; a word bash cannot expand is skipped.
func TestNetBraceSoundnessLongSequences(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	words := []string{
		"d{1..4095}x", "d{1..4096}x", "d{1..4097}x", "d{1..5000}x",
		"d{0..5000}/s", "d{{1..5000},x}y", "s{5000..1..-1}", "s{0001..5000}",
		"a{1..4097}b{c,d}", "{1..5000}{a..c}", "x{-5000..-1}",
		"{0..-9223372036854775808}", "{a..z..-9223372036854775808}",
		"{1..-9223372036854775807}", "{-9223372036854775808..0}",
		"{9223372036854775806..9223372036854775807..2}",
		"{-9223372036854775807..-9223372036854775805}",
		"{9223372036854775807..9223372036854775807}",
		"d{1..3}{-9223372036854775808..0}",
		"{9223372036854775807..9223372036854775808}",
		"{1..10..9223372036854775807}", "{1..10..-9223372036854775807}",
		// Round 8: increments and ends longer than 64 characters, zero-padded.
		"d{1..5..000000000000000000000000000000000000000000000000000000000000001}x", "d{000000000000000000000000000000000000000000000000000000000000001..5}x", "e{e..e..000000000000000000000000000000000000000000000000000000000000001}/s",
		"s{n..n..00000000000000000000000000000000000000000000000000000000000000000000001}", "s{q..o..000000000000000000000000000000000000000000000000000000000000002}n", "x{1..3..-000000000000000000000000000000000000000000000000000000000000001}",
		"{00000000000000000000000000000000000000000000000000000000000000000000001..00000000000000000000000000000000000000000000000000000000000000000000003}", "set{u..s..0}in{g..g..000000000000000000000000000000000000000000000000000000000000001}",
		"setting{s,{x}}.jso{n..n..1}", "setting{s,x{y}z}.jso{n..n..01}",
		"{.,{x}}claude/setting{s,{y}}.jso{n..n..-01}",
	}
	for _, word := range words {
		out, err := exec.Command(bash, "--norc", "--noprofile", "-c", "printf '%s\\n' "+word).Output()
		if err != nil {
			continue
		}
		ms, _ := levelOneChars(word, "")
		atoms := []*netPattern{newNetPattern(braceAtoms(ms, false), false)}
		exact, _ := buildPatterns(&netBudget{}, ms, true, false, false)
		for _, w := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			if !netAccepts(atoms, w) {
				t.Errorf("word %q: bash makes %q, the brace atoms do not match it", word, w)
			}
			if !netAccepts(exact, w) {
				t.Errorf("word %q: bash makes %q, the exact patterns do not match it", word, w)
			}
		}
	}
}

// randomNestedBraceWord returns a word with the two shapes of round 8: a
// group with no comma inside an item of a list (bash keeps the braces of
// the inner group as text only when every group around it is kept too),
// and sequences with a long, zero-padded or negative increment or end.
func randomNestedBraceWord(rng *rand.Rand) string {
	for {
		if w, n := nestedBraceWord(rng); n <= 200 {
			return w
		}
	}
}

// nestedBraceWord returns a word and an upper bound of the number of words
// bash makes from it. Every sequence it writes makes at most 4 words.
func nestedBraceWord(rng *rand.Rand) (string, int) {
	zeros := func() string { return strings.Repeat("0", []int{0, 1, 3, 62, 70}[rng.Intn(5)]) }
	seq := func() string {
		ends := [][2]string{{"n", "n"}, {"a", "c"}, {"q", "o"}, {"1", "3"}, {"5", "2"}, {"e", "e"}, {"-2", "1"}}
		e := ends[rng.Intn(len(ends))]
		if rng.Intn(3) == 0 {
			e[0] = zeros() + e[0]
		}
		inc := []string{"", "1", "0", "-1", "2", "-01"}[rng.Intn(6)]
		if inc == "" {
			return "{" + e[0] + ".." + e[1] + "}"
		}
		return "{" + e[0] + ".." + e[1] + ".." + zeros() + inc + "}"
	}
	var item func(depth int) (string, int)
	group := func(depth int) (string, int) {
		switch rng.Intn(5) {
		case 0:
			w, n := item(depth + 1)
			return "{" + w + "}", n
		case 1:
			return seq(), 4
		case 2:
			return "{}", 1
		default:
			var parts []string
			total := 0
			for k := rng.Intn(3) + 2; k > 0; k-- {
				w, n := item(depth + 1)
				parts = append(parts, w)
				total += n
			}
			return "{" + strings.Join(parts, ",") + "}", total
		}
	}
	item = func(depth int) (string, int) {
		var sb strings.Builder
		total := 1
		for k := rng.Intn(3); k >= 0; k-- {
			if depth < 3 && rng.Intn(2) == 0 {
				w, n := group(depth)
				sb.WriteString(w)
				total *= n
			} else {
				sb.WriteString([]string{"s", "x", "y", ".", "/", ""}[rng.Intn(6)])
			}
		}
		return sb.String(), total
	}
	var sb strings.Builder
	total := 1
	for k := rng.Intn(3) + 1; k > 0; k-- {
		w, n := item(0)
		g, m := group(0)
		sb.WriteString(w + g)
		total *= n * m
	}
	return sb.String(), total
}

// Every word real bash makes from a random word with nested groups in list
// items and long or zero-padded sequences is matched by the brace atoms and
// by the patterns of the exact reading. A word that makes more than 200
// words is not made, to keep the run short. TG_BRACE_SEED and TG_BRACE_N
// choose another seed and count.
func TestNetBraceSoundnessNestedAgainstBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	n := 2000
	seed := int64(8)
	if s := os.Getenv("TG_BRACE_SEED"); s != "" {
		fmt.Sscan(s, &seed)
	}
	if s := os.Getenv("TG_BRACE_N"); s != "" {
		fmt.Sscan(s, &n)
	}
	// bash 3.2, the bash of macOS, makes no sequence with an increment and
	// keeps its text. The check reads braces as bash 4 and later do; a word
	// that keeps a brace cannot be a path without one, so with bash 3.2 such
	// a word is not checked.
	ver, err := exec.Command(bash, "--norc", "--noprofile", "-c", "echo ${BASH_VERSINFO[0]}").Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	major := strings.TrimSpace(string(ver))
	oldBash := major == "2" || major == "3"
	rng := rand.New(rand.NewSource(seed))
	words := make([]string, n)
	var script strings.Builder
	for i := range words {
		words[i] = randomNestedBraceWord(rng)
		script.WriteString("printf '%s\\n' " + words[i] + "; echo '\x01'\n")
	}
	run := exec.Command(bash, "--norc", "--noprofile", "-s")
	run.Stdin = strings.NewReader(script.String())
	out, err := run.Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	groups := strings.Split(strings.TrimSuffix(string(out), "\x01\n"), "\x01\n")
	if len(groups) != n {
		t.Fatalf("bash gave %d groups, want %d", len(groups), n)
	}
	checked, misses := 0, 0
	for i, g := range groups {
		ws := strings.Split(strings.TrimSuffix(g, "\n"), "\n")
		checked++
		ms, _ := levelOneChars(words[i], "")
		atoms := []*netPattern{newNetPattern(braceAtoms(ms, false), false)}
		exact, _ := buildPatterns(&netBudget{}, ms, true, false, false)
		for _, w := range ws {
			if oldBash && strings.Contains(w, "{") {
				continue
			}
			if !netAccepts(atoms, w) {
				misses++
				t.Errorf("word %q: bash makes %q, the brace atoms do not match it", words[i], w)
			}
			if !netAccepts(exact, w) {
				misses++
				t.Errorf("word %q: bash makes %q, the exact patterns do not match it", words[i], w)
			}
		}
	}
	t.Logf("seed %d, bash %s: %d words checked, %d misses", seed, major, checked, misses)
}

// TestNetRemoteMountUnknown: the check does not look into a FUSE or network
// mount. A write that reaches one is denied, a read stays allowed, and the
// mount list reads the octal escapes of mountinfo.
func TestNetRemoteMountUnknown(t *testing.T) {
	if got := unescapeMount(`/mnt/my\040drive`); got != "/mnt/my drive" {
		t.Fatalf("unescapeMount = %q", got)
	}
	if !netRemoteType("fuse.sshfs") || !netRemoteType("nfs4") || netRemoteType("fusectl") || netRemoteType("ext4") {
		t.Fatal("netRemoteType")
	}
	netRemoteOnce.Do(loadRemoteMounts)
	saved := netRemoteMounts
	t.Cleanup(func() { netRemoteMounts = saved })
	h := t.TempDir()
	mnt := filepath.Join(h, "mnt")
	if err := os.MkdirAll(filepath.Join(mnt, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A mount list holds physical paths: on macOS the temp dir is under
	// the link /var, and the mount is at /private/var/...
	physMnt, err := filepath.EvalSymlinks(mnt)
	if err != nil {
		t.Fatal(err)
	}
	netRemoteMounts = append(append([]string{}, saved...), filepath.ToSlash(mnt), filepath.ToSlash(physMnt))
	prefixes := []string{filepath.Join(h, ".claude", "settings.json")}
	for _, c := range []struct {
		cmd  string
		deny bool
	}{
		{"cp a " + mnt + "/x", true},
		{"echo x > " + mnt + "/sub/y", true},
		{"cp a " + h + "/m*/x", true},
		{"cat " + mnt + "/x", false},
		{"cp a " + h + "/other", false},
	} {
		hit, why := netCheck(c.cmd, prefixes, []string{h})
		if hit != c.deny {
			t.Errorf("%q: deny=%v (%q), want %v", c.cmd, hit, why, c.deny)
		}
	}
}

// FuzzNetCheck runs the check of shell text on random commands: it must not
// panic and must end in under 1 s.
func FuzzNetCheck(f *testing.F) {
	for _, s := range []string{
		"echo x > .claude/settings.json",
		"eval tee '.claude/settings.{json,{1..70}}'",
		`python3 -c 'print({"a":1,"b":{"c":2}})'`,
		"tee .claude/settings.{x}y,json}",
		"echo x 1>&0- > /dev/stdout",
		"cd $(printf .cl)aude && echo pwn > settings.json",
		"ls {a..e}* node_modules/{.cache,{a..z}*}",
		strings.Repeat("{a,", 50) + strings.Repeat("}", 50),
		"tee d{1..5000}/settings.json",
		"echo {-9223372036854775808..9223372036854775807}",
		"ls {-9223372036854775808..9223372036854775807}",
		"echo {0..-9223372036854775808}",
		"echo {a..z..-9223372036854775808}",
		"echo {1..-9223372036854775807}",
		"echo {9223372036854775806..9223372036854775807..2}",
		"tee {-9223372036854775808..0}",
		"python3 w.py s{5000..1..-1}/settings.json",
		"$(\\",   // an unclosed $( at the end made levelOneChars panic
		"\x00 *", // a pattern as an operand of a program the check cannot know
	} {
		f.Add(s)
	}
	home := f.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".claude"), filepath.Join(home, "dlink")); err != nil {
		f.Fatal(err)
	}
	prefixes := []string{filepath.Join(home, ".claude", "settings.json")}
	f.Fuzz(func(t *testing.T, cmd string) {
		start := time.Now()
		netCheck(cmd, prefixes, []string{home})
		if d := time.Since(start); d > time.Second {
			t.Fatalf("netCheck took %s on %q", d, cmd)
		}
	})
}
