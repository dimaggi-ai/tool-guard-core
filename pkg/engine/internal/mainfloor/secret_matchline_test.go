package mainfloor

import (
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// secretMatchLineLinear is the line-by-line scan that secretMatchLine
// replaced. It is kept as the reference for the equivalence test.
func secretMatchLineLinear(text string, newlines []int, start, end int) (string, int) {
	if len(newlines) == 0 {
		newlines = []int{len(text)}
	}
	previous, lineStart, lineEnd, startLine, lastLine := 0, 0, 0, 0, 0
	lineSet := false
	for lineNumber, newline := range newlines {
		lastLine = lineNumber
		if previous <= start && start < newline {
			lineSet = true
			startLine, lineStart, lineEnd = lineNumber, previous, newline
		}
		if previous < end && end <= newline {
			lineEnd = newline
		}
		previous = newline
	}
	if !lineSet {
		startLine = lastLine + 1
		lineEnd = end
		for lineEnd < len(text) && text[lineEnd] != '\n' && text[lineEnd] != '\r' {
			lineEnd++
		}
	}
	if end > lineEnd {
		lineEnd = end
	}
	return text[lineStart:lineEnd], startLine
}

func newlineOffsets(text string) []int {
	var out []int
	for i := range text {
		if text[i] == '\n' {
			out = append(out, i)
		}
	}
	return out
}

func TestSecretMatchLineMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := "ab\n\r"
	fixed := []string{"", "a", "\n", "\n\n", "ab\n", "\nab", "a\r\nb\n", "ab\ncd\r\nef"}
	for iter := 0; iter < 4000; iter++ {
		var text string
		if iter < len(fixed) {
			text = fixed[iter]
		} else {
			b := make([]byte, rng.Intn(24))
			for i := range b {
				b[i] = alphabet[rng.Intn(len(alphabet))]
			}
			text = string(b)
		}
		newlines := newlineOffsets(text)
		for start := 0; start <= len(text); start++ {
			for end := start; end <= len(text); end++ {
				gotLine, gotNumber := secretMatchLine(text, newlines, start, end)
				wantLine, wantNumber := secretMatchLineLinear(text, newlines, start, end)
				if gotLine != wantLine || gotNumber != wantNumber {
					t.Fatalf("text %q start %d end %d: got (%q, %d), want (%q, %d)",
						text, start, end, gotLine, gotNumber, wantLine, wantNumber)
				}
			}
		}
	}
}

// denseSecretLines builds size bytes: blank lines in the first half, then
// one provider-format token per line. The token is split here so the source
// holds no complete key string; its value is synthetic.
func denseSecretLines(size int) string {
	token := "ghp_" + "7Qm4Zv8Lr2Px6Nb9Yk3Jc5Hd1Wf0TsUaEeOi\n"
	text := strings.Repeat("\n", size/2) + strings.Repeat(token, (size-size/2)/len(token))
	return text
}

// A maximum-size field with a match on every line took 8 to 22 seconds when
// each match scanned every line; with binary search it takes about 0.1 s.
func TestSecretClassifyDenseMultilineIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 1 MiB")
	}
	text := denseSecretLines(maximumSecretMaxBytes)
	began := time.Now()
	result := classifySecrets(text, maximumSecretMaxBytes)
	elapsed := time.Since(began)
	assertManyMatches(t, text, `ghp_[0-9A-Za-z]{36}`, 10000)
	if len(result.Findings) == 0 {
		t.Fatal("dense input produced no finding")
	}
	assertBoundedByScan(t, text, elapsed)
	t.Logf("1 MiB dense multiline: %s, %d findings", elapsed, len(result.Findings))
}

// assertBoundedByScan fails when classifying text took more than eight times
// the rule-regex scan of the same text, measured here on the same machine,
// plus 250 ms. The scan is work classifySecrets cannot avoid, so the bound
// holds on slow runners and under the race detector. Without the race
// detector, a per-match rescan of a long line (10 s or more at 1 MiB, about
// 18 times the scan) exceeds it. The linear code takes 3 to 4.3 times the
// scan, the higher figure on a hosted runner with coverage on; the race detector slows the scan more than
// the rescan, so only the non-race run catches that regression.
func assertBoundedByScan(t *testing.T, text string, elapsed time.Duration) {
	t.Helper()
	rules, _, err := loadSecretRules()
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(text)
	began := time.Now()
	for _, r := range rules {
		if r.Path != "" || (len(r.Keywords) > 0 && !containsSecretKeyword(lower, r.Keywords)) {
			continue
		}
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			r.re.FindStringSubmatch(text[loc[0]:loc[1]])
		}
	}
	scan := time.Since(began)
	if limit := 8*scan + 250*time.Millisecond; elapsed > limit {
		t.Fatalf("classifying took %s; the rule scan alone took %s, limit %s", elapsed, scan, limit)
	}
	t.Logf("classify %s, rule scan %s", elapsed, scan)
}

// assertManyMatches fails unless pattern matches text at least min times, so
// a timing test cannot pass on an input that has few matches.
func assertManyMatches(t *testing.T, text, pattern string, min int) {
	t.Helper()
	if got := len(regexp.MustCompile(pattern).FindAllStringIndex(text, -1)); got < min {
		t.Fatalf("input has %d matches of %s, want at least %d", got, pattern, min)
	}
}

// denseSecretSingleLine builds size bytes on one line: repeated api_key
// assignments, each a generic-api-key candidate. The value is synthetic.
func denseSecretSingleLine(size int) string {
	assignment := "api_key=SYNTHqk0123456789 "
	return strings.Repeat(assignment, size/len(assignment))
}

// A dense last line with no final newline, after an earlier line, took
// 10.3 s when each match scanned from its end to the end of the text.
func TestSecretClassifyDenseUnterminatedLastLineIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 1 MiB")
	}
	text := "header\n" + denseSecretSingleLine(maximumSecretMaxBytes-len("header\n"))
	assertManyMatches(t, text, `api_key=SYNTHqk0123456789`, 10000)
	began := time.Now()
	result := classifySecrets(text, maximumSecretMaxBytes)
	elapsed := time.Since(began)
	if !slices.ContainsFunc(result.Findings, func(f secretFinding) bool { return f.RuleID == "generic-api-key" }) {
		t.Fatalf("unterminated last line found %v, want generic-api-key", result.Findings)
	}
	assertBoundedByScan(t, text, elapsed)
	t.Logf("1 MiB dense unterminated last line: %s, %d findings", elapsed, len(result.Findings))
}

// One long line with many matches took 10.6 s when line-target allowlist
// regexes rescanned the whole line for each match; it now takes about 1.8 s.
func TestSecretClassifyDenseSingleLineIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 1 MiB")
	}
	text := denseSecretSingleLine(maximumSecretMaxBytes)
	assertManyMatches(t, text, `api_key=SYNTHqk0123456789`, 10000)
	began := time.Now()
	result := classifySecrets(text, maximumSecretMaxBytes)
	elapsed := time.Since(began)
	if !slices.ContainsFunc(result.Findings, func(f secretFinding) bool { return f.RuleID == "generic-api-key" }) {
		t.Fatalf("single-line input found %v, want generic-api-key", result.Findings)
	}
	assertBoundedByScan(t, text, elapsed)
	t.Logf("1 MiB dense single line: %s, %d findings", elapsed, len(result.Findings))
}

func BenchmarkSecretClassifyDenseMultiline1MiB(b *testing.B) {
	text := denseSecretLines(maximumSecretMaxBytes)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifySecrets(text, maximumSecretMaxBytes)
	}
}
