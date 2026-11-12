package main

// The example README lists the shell forms the protected-path check reads.
// The fourth independent review (2026-11-10) found that list ahead of the
// code. This test reads the program lists from pkg/engine/protect.go and
// requires the README bullets to name the same programs.

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

const backtick = "\x60"

// engineProgList returns the keys of one map[string]bool literal in
// pkg/engine/protect.go.
func engineProgList(t *testing.T, source, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)var ` + name + ` = map\[string\]bool\{(.*?)\n?\}`).FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("pkg/engine/protect.go no longer declares %s as a map literal", name)
	}
	var keys []string
	for _, k := range regexp.MustCompile(`"([a-z]+)": true`).FindAllStringSubmatch(m[1], -1) {
		keys = append(keys, k[1])
	}
	if len(keys) == 0 {
		t.Fatalf("%s has no entries", name)
	}
	sort.Strings(keys)
	return keys
}

// engineProgListAllowDigits is engineProgList for names that may hold a digit.
func engineProgListAllowDigits(t *testing.T, source, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)var ` + name + ` = map\[string\]bool\{(.*?)\n?\}`).FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("%s is no longer declared as a map literal", name)
	}
	var keys []string
	for _, k := range regexp.MustCompile(`"([a-z0-9]+)": true`).FindAllStringSubmatch(m[1], -1) {
		keys = append(keys, k[1])
	}
	sort.Strings(keys)
	return keys
}

// readmeBullet returns the bullet of the Protected paths section that holds
// marker, on one line.
func readmeBullet(t *testing.T, readme, marker string) string {
	t.Helper()
	i := strings.Index(readme, "## Protected paths")
	j := strings.Index(readme, "## Environment variables")
	if i < 0 || j < i {
		t.Fatal("example README lost the section Protected paths or Environment variables")
	}
	for _, item := range strings.Split(readme[i:j], "\n- ") {
		item = oneLine(strings.SplitN(item, "\n\n", 2)[0])
		if strings.Contains(item, marker) {
			return item
		}
	}
	t.Fatalf("the Protected paths section has no bullet with %q", marker)
	return ""
}

func backtickedWords(s string) []string {
	var out []string
	for _, m := range regexp.MustCompile(backtick+"([^"+backtick+"]+)"+backtick).FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestReadmeShellFormsMatchEngine(t *testing.T) {
	source := readRepoFile(t, "pkg", "engine", "protect.go")
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")

	check := func(marker string, want []string, drop ...string) {
		t.Helper()
		bullet := readmeBullet(t, readme, marker)
		var got []string
	words:
		for _, w := range backtickedWords(bullet) {
			for _, d := range drop {
				if w == d {
					continue words
				}
			}
			got = append(got, w)
		}
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("README bullet %q names %v; pkg/engine/protect.go has %v", marker, got, want)
		}
	}

	mutating := append(engineProgList(t, source, "mutatingProgs"), "sed -i", "dd of=")
	check("the commands ", mutating)
	if !strings.Contains(source, `case "sed":`) || !strings.Contains(source, `case "dd":`) {
		t.Error("isMutatingProg no longer handles sed and dd; update the README bullet and this test")
	}
	check("runs with "+backtick+"-c"+backtick, engineProgList(t, source, "shellInterpreters"), "-c", "-lc", "-ce")
	check("together make one of the paths", engineProgList(t, source, "intoDirectoryProgs"))
	check("follows one of these wrappers", engineProgListAllowDigits(t, readRepoFile(t, "pkg", "engine", "reversibility.go"), "shellWrapperProgs"))
	check("in the same command, when", []string{"cd DIR", "pushd DIR", "DIR", "DIR"}, "..", "cd ~/proj && echo x > ../.claude/settings.json")

	// Rule 1: the read-only programs.
	readOnly := append(engineProgListAllowDigits(t, readRepoFile(t, "pkg", "engine", "protect_mention.go"), "readOnlyProgs"), "[")
	sort.Strings(readOnly)
	i := strings.Index(readme, "one of these read-only programs:")
	if i < 0 {
		t.Fatal("the README no longer lists the read-only programs")
	}
	para := strings.SplitN(readme[i:], "\n\n", 2)[0]
	if got := backtickedWords(para); strings.Join(got, " ") != strings.Join(readOnly, " ") {
		t.Errorf("README read-only programs %v; pkg/engine/protect_mention.go has %v", got, readOnly)
	}
	if n := strings.Count(strings.SplitN(readme[strings.Index(readme, "in one of these six ways:"):], "\n\nWhen the text names", 2)[0], "\n- "); n != 6 {
		t.Errorf("the README says a path is named in six ways and lists %d", n)
	}
	check("follows a shell keyword", []string{"if", "then", "do", "{", "!"})
	for _, k := range []string{"if", "then", "do", "{", "!"} {
		if !strings.Contains(source, "\""+k+"\": true") {
			t.Errorf("shellPrefixWords in pkg/engine/protect.go no longer holds %q", k)
		}
	}
	check("on a directory above", engineProgList(t, source, "ancestorMutatingProgs"), "mv ~/.claude ~/.claude-old")

	if n := strings.Count(readmeSectionForms(readme), "\n- "); n != 12 {
		t.Errorf("the README says the hook checks twelve forms and lists %d", n)
	}
	requireSentences(t, readme,
		"It checks twelve forms:",
		"It applies two rules.",
		"The hook denies the command unless every program in it is one of these read-only programs:",
		"The text names a path when it holds the path in one of these six ways:",
		"When the text names a protected path, the hook also denies a command that holds a comment ("+backtick+"#"+backtick+"), a here-document, "+backtick+"${...}"+backtick+", "+backtick+"$((...))"+backtick+", "+backtick+"case"+backtick+" or a carriage return.",
		"A command that sets a variable or starts the program through a wrapper, as in "+backtick+"PATH=/x cat FILE"+backtick+" or "+backtick+"env cat FILE"+backtick+", does not count as read-only.",
		"On macOS and Windows the hook compares a path with a protected path without letter case, so "+backtick+"echo x > ~/.CLAUDE/settings.json"+backtick+" is denied there.",
		"On another system it does this when it finds that the directory of the protected path ignores letter case.",
		"The hook reads them as two names, so it does not see a protected path that is written in the other form.",
		"Two more programs count as read-only when their words cannot name an output file.",
		"A word that starts with "+backtick+"~+"+backtick+", "+backtick+"~-"+backtick+" or "+backtick+"~NAME"+backtick+" also counts as the name of a protected path.",
		"So "+backtick+"uniq x ~+/settings.json"+backtick+" is denied and "+backtick+"cat ~+/settings.json"+backtick+" is allowed.",
		"Neither counts when one of its words holds "+backtick+"{"+backtick+", "+backtick+"*"+backtick+", "+backtick+"?"+backtick+" or "+backtick+"["+backtick+", because bash can turn such a word into an option or into a second file name.",
		backtick+"sort"+backtick+" counts when no word starts with "+backtick+"--"+backtick+" and no option holds "+backtick+"o"+backtick+" or "+backtick+"T"+backtick+".",
		backtick+"uniq"+backtick+" counts when it has at most one file name and no "+backtick+"--"+backtick+".",
		"So "+backtick+"ls ~/.claude/* | sort"+backtick+" is allowed, and "+backtick+"sort -o FILE"+backtick+" and "+backtick+"uniq ~/.claude/*"+backtick+" are not.",
		"So "+backtick+"python3 edit.py ~/.claude/settings.json"+backtick+" and "+backtick+"git checkout ~/.claude/settings.json"+backtick+" are denied, and "+backtick+"cat ~/.claude/settings.json"+backtick+" is allowed.",
		"or it builds the path from parts ("+backtick+"printf"+backtick+", "+backtick+"eval"+backtick+").",
		"The rule reads the text and not what the command does with it, so "+backtick+"git commit -m \"change ~/.claude/settings.json\""+backtick+" is denied too.",
		"A shell with "+backtick+"-c"+backtick+" and no other option counts as read-only when the command it runs does.",
		"and any other word of one of these commands that holds a variable, as in "+backtick+"sed -i \"s/$OLD/$NEW/\" FILE"+backtick+", because the hook cannot tell which word is the file,",
		"The hook reads the path under `DIR`, also a path with `..`, as in `cd ~/proj && echo x > ../.claude/settings.json`.",
		"It goes to a directory that the command text does not name, as in `cd $DIR`, and writes a relative path there.",
		"The hook does not check how a command uses a directory that it names, so "+backtick+"ls ~/.tool-guard > list.txt"+backtick+" is denied too.",
		"These two rules are the whole check.",
		"The hook does not see a write when the command text does not name the path and the write is not one of the twelve forms.",
		"It changes a whole directory above the path, as in "+backtick+"find ~/.claude -delete"+backtick+".",
		"The hook does not read a script that a shell runs from a file.",
		"Other ways can exist that are not in this paragraph.",
		"a path built from a variable or a command substitution, which it denies,",
		"When the name of the program in that command comes from a variable, the hook denies the call,",
		"An agent that can run a shell can change a protected file in one of these ways.")
}

// readmeSectionForms returns the list that follows "It checks seven forms:".
func readmeSectionForms(readme string) string {
	i := strings.Index(readme, "It checks twelve forms:")
	if i < 0 {
		return ""
	}
	rest := readme[i:]
	if j := strings.Index(rest, "\n\nThese two rules"); j > 0 {
		return rest[:j]
	}
	return rest
}
