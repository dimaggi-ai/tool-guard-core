package engine

// Property tests of the check of shell text (protect_net.go): the sigma
// reading is unchanged by quote removal, and the brace atoms hold every
// word real bash makes from a brace list. FuzzNetCheck runs the whole check
// on random commands.

import (
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
	out, err := exec.Command(bash, "--norc", "--noprofile", "-c", script.String()).Output()
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
