package commandclassify

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type corpusCase struct {
	Name     string   `json:"name"`
	Input    string   `json:"input"`
	Decision Decision `json:"decision"`
}

func TestSyntheticCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/gh-read-corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if names[c.Name] {
				t.Fatal("duplicate case name")
			}
			names[c.Name] = true
			got := Classify(c.Input)
			if got.Decision != c.Decision {
				t.Fatalf("%q: %+v; want %s", c.Input, got, c.Decision)
			}
			checkResult(t, c.Input, got)
		})
	}
}
func checkResult(t *testing.T, input string, r Result) {
	t.Helper()
	if r.Decision != ReadOnlyCandidate && r.Decision != Escalate {
		t.Fatal(r)
	}
	if r.Reason == "" || r.Span.Start < 0 || r.Span.End < r.Span.Start || r.Span.End > len(input) {
		t.Fatalf("invalid result: %+v", r)
	}
	last := 0
	for _, w := range r.Words {
		if w.Span.Start < last || w.Span.End <= w.Span.Start || w.Span.End > len(input) {
			t.Fatalf("invalid word span: %+v", w)
		}
		last = w.Span.End
	}
	if !reflect.DeepEqual(r, Classify(input)) {
		t.Fatal("classification must be deterministic")
	}
}
func TestExactSourceSpans(t *testing.T) {
	input := `  gh pr list --label 'help wanted' --limit=20`
	r := Classify(input)
	if r.Decision != ReadOnlyCandidate || r.Command != "pr list" {
		t.Fatal(r)
	}
	if r.Span != (Span{0, len(input)}) {
		t.Fatal(r.Span)
	}
	if r.Words[4].Value != "help wanted" || input[r.Words[4].Span.Start:r.Words[4].Span.End] != `'help wanted'` {
		t.Fatal(r.Words)
	}
	for _, c := range []struct{ input, reason, source string }{
		{`gh pr list --limit 0`, "invalid_option_value", "--limit 0"},
		{`gh pr list --json title,unknown`, "invalid_option_value", "--json title,unknown"},
		{`gh pr list --limit 3 -L 4`, "repeated_option", "-L"},
		{`gh pr list; gh pr create`, "active_shell_syntax", ";"},
		{`gh repo list --fork --source`, "conflicting_options", "--fork"},
		{`gh pr view --comments=true`, "unsupported_boolean_value", "--comments=true"},
	} {
		r := Classify(c.input)
		if r.Decision != Escalate || r.Reason != c.reason || c.input[r.Span.Start:r.Span.End] != c.source {
			t.Fatalf("%s: %+v", c.input, r)
		}
	}
}
func TestAllOptionValuesConsumedAndValidated(t *testing.T) {
	for _, prefix := range []string{"gh --repo example-org/example-repo pr list", "gh pr --repo example-org/example-repo list", "gh pr list -R example-org/example-repo"} {
		for _, tail := range []string{" --limit 1", " -L 1000", " --state closed --json number,title", ` --label "help wanted"`} {
			if r := Classify(prefix + tail); r.Decision != ReadOnlyCandidate {
				t.Fatal(r)
			}
		}
		for _, tail := range []string{" --limit", " --limit 0", " --limit -1", " --limit +1", " --limit 01", " --limit 1001", " --limit 1e2", " --limit 1.0", " --limit 3 stray", " --limit 3 --limit 4", " --json title,", " --json title,title", " --json TITLE", " --json title,,body", " --state merged stray", " --repo example-org/second", " --state=", " --label -X"} {
			if r := Classify(prefix + tail); r.Decision != Escalate {
				t.Fatalf("unexpected candidate: %q %+v", prefix+tail, r)
			}
		}
	}
}
func TestCorrectedRetryDoesNotReuseRejectedState(t *testing.T) {
	valid := "gh issue list --state open --limit 20"
	want := Classify(valid)
	for _, bad := range []string{"gh issue list --state merged", "gh issue list --limit 0", "gh issue list && gh issue close 1", "gh issue list --json title,title"} {
		if Classify(bad).Decision != Escalate {
			t.Fatal(bad)
		}
		if got := Classify(valid); got.Decision != ReadOnlyCandidate || !reflect.DeepEqual(got, want) {
			t.Fatal(got)
		}
	}
}
func TestBounds(t *testing.T) {
	for _, s := range []string{strings.Repeat("x", MaxInputBytes+1), "gh pr list --label '" + strings.Repeat("x", MaxWordBytes+1) + "'", "gh " + strings.Repeat("x ", MaxWords), "gh pr list " + strings.Repeat("(", 4000), "gh pr list\x00"} {
		r := Classify(s)
		if r.Decision != Escalate {
			t.Fatal(r)
		}
		checkResult(t, s, r)
	}
}
func TestConcurrentClassification(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run("independent", func(t *testing.T) { t.Parallel(); TestCorrectedRetryDoesNotReuseRejectedState(t) })
	}
}
func FuzzClassify(f *testing.F) {
	for _, s := range []string{"gh pr view 1", `gh pr list --label '$(literal)'`, "gh issue list --json title", "gh api /user -XPOST", "gh pr list; x", "\x00", "gh '", `gh \`, "gh repo ls --visibility public", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkResult(t, s, Classify(s)) })
}
