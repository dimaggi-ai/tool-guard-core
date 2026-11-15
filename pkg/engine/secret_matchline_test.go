package engine

import (
	"math/rand"
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
	if len(result.Findings) == 0 {
		t.Fatal("dense input produced no finding; the test no longer exercises many matches")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("classifying 1 MiB of dense matches took %s", elapsed)
	}
	t.Logf("1 MiB dense multiline: %s, %d findings", elapsed, len(result.Findings))
}

func BenchmarkSecretClassifyDenseMultiline1MiB(b *testing.B) {
	text := denseSecretLines(maximumSecretMaxBytes)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifySecrets(text, maximumSecretMaxBytes)
	}
}
