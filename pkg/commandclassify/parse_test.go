package commandclassify

import (
	"reflect"
	"strings"
	"testing"
)

func TestLiteralWords(t *testing.T) {
	for _, c := range []struct {
		input  string
		values []string
	}{
		{"gh\tpr list", []string{"gh", "pr", "list"}},
		{`gh pr list --label 'help wanted'`, []string{"gh", "pr", "list", "--label", "help wanted"}},
		{`gh pr list --label help\ wanted`, []string{"gh", "pr", "list", "--label", "help wanted"}},
		{`gh pr list --label pre'fix'" suffix"`, []string{"gh", "pr", "list", "--label", "prefix suffix"}},
		{`gh pr list --label '$(literal); & # > * !'`, []string{"gh", "pr", "list", "--label", "$(literal); & # > * !"}},
		{`gh pr list --label "\$literal"`, []string{"gh", "pr", "list", "--label", "$literal"}},
		{`gh pr list --label "a;b|c#d>e"`, []string{"gh", "pr", "list", "--label", "a;b|c#d>e"}},
	} {
		words, err := parse(c.input)
		if err != nil {
			t.Fatalf("%q: %+v", c.input, err)
		}
		var got []string
		for _, w := range words {
			got = append(got, w.Value)
		}
		if !reflect.DeepEqual(got, c.values) {
			t.Fatalf("%q: %q", c.input, got)
		}
	}
}
func TestRejectActiveOrUnsupportedSyntax(t *testing.T) {
	for _, suffix := range []string{";x", "|x", "||x", "&&x", "&x", ">x", "<x", "(x)", "{x}", "[x]", "*", "?", "$x", "${x}", "$(x)", "`x`", "!x", "#comment", "~x", "\n", "\r", "\x00", "\x1b", "\x7f", "é", "\u202e"} {
		if _, err := parse("gh pr list " + suffix); err == nil {
			t.Fatalf("accepted %q", suffix)
		}
	}
	for _, s := range []string{"gh '", `gh "`, "gh " + string('\\'), `gh "\q"`, `gh \a`, `gh "$x"`, "gh \"`x`\"", `gh "!x"`, "gh 'line\nbreak'", "gh \\\npr list"} {
		if _, err := parse(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestParserLimitsAreInclusive(t *testing.T) {
	if _, err := parse(strings.Repeat("x", MaxWordBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(strings.Repeat("x", MaxWordBytes+1)); err == nil || err.reason != "word_too_large" {
		t.Fatal(err)
	}
	if words, err := parse(strings.Repeat("x ", MaxWords)); err != nil || len(words) != MaxWords {
		t.Fatal(err)
	}
	if _, err := parse(strings.Repeat("x ", MaxWords+1)); err == nil || err.reason != "too_many_words" {
		t.Fatal(err)
	}
	// Padding does not evade the whole-input byte bound.
	if _, err := parse("gh" + strings.Repeat(" ", MaxInputBytes-2)); err != nil {
		t.Fatal(err)
	}
	if _, err := parse("gh" + strings.Repeat(" ", MaxInputBytes-1)); err == nil || err.reason != "input_too_large" {
		t.Fatal(err)
	}
}
