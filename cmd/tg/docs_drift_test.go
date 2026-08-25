package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestDocsCLICommandsMatchUsageAndDispatch(t *testing.T) {
	usageCommands := regexpMatches(t, `(?m)^  tg ([a-z][a-z-]*)\b`, usage)
	dispatchCommands := commandDispatchNames(t, "main.go")
	documentedCommands := regexpMatches(
		t,
		"(?m)^\\| `tg ([a-z][a-z-]*)` \\|",
		readRepoFile(t, "docs", "cli-reference.md"),
	)

	if !reflect.DeepEqual(dispatchCommands, usageCommands) {
		t.Fatalf("CLI dispatch commands %v do not match usage commands %v", dispatchCommands, usageCommands)
	}
	if !reflect.DeepEqual(documentedCommands, usageCommands) {
		t.Fatalf("documented CLI commands %v do not match usage commands %v", documentedCommands, usageCommands)
	}
}

func TestDocsLintChecksMatchImplementation(t *testing.T) {
	implemented := lintRuleNames(t, "main.go", "cmdLint", "lintPolicy")
	doc := readRepoFile(t, "docs", "creating-policies.md")
	documented := regexpMatches(t, "(?m)^\\| `([a-z][a-z0-9-]+)` \\| (?:warn|error) \\|", doc)
	sort.Strings(documented)

	if !reflect.DeepEqual(documented, implemented) {
		t.Fatalf("documented lint checks %v do not match implemented checks %v", documented, implemented)
	}

	countMatch := regexp.MustCompile(`runs\s+([0-9]+)\s+checks`).FindStringSubmatch(doc)
	if len(countMatch) != 2 {
		t.Fatal("docs/creating-policies.md must state the lint count as 'runs N checks'")
	}
	count, err := strconv.Atoi(countMatch[1])
	if err != nil {
		t.Fatalf("parse documented lint count: %v", err)
	}
	if count != len(implemented) {
		t.Fatalf("documented lint count is %d; implementation exposes %d checks", count, len(implemented))
	}
}

func TestDocsClassifierListMatchesConditionSchema(t *testing.T) {
	implemented := conditionClassifierNames(t, filepath.Join("..", "..", "pkg", "domain", "policy.go"))
	documented := regexpMatches(
		t,
		"(?m)^\\| `([a-z]+_classify)` \\|",
		readRepoFile(t, "docs", "architecture.md"),
	)
	sort.Strings(documented)

	if !reflect.DeepEqual(documented, implemented) {
		t.Fatalf("documented classifiers %v do not match Condition schema %v", documented, implemented)
	}
}

func TestDocsIndexListsEveryGuide(t *testing.T) {
	index := readRepoFile(t, "docs", "README.md")
	guides, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil {
		t.Fatalf("list documentation guides: %v", err)
	}
	for _, guide := range guides {
		name := filepath.Base(guide)
		if name == "README.md" {
			continue
		}
		if !strings.Contains(index, "]("+name+")") {
			t.Errorf("docs/README.md does not link to %s", name)
		}
	}
}

func TestChangelogReleaseLinksReferenceExistingTags(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(repoRoot, ".git")); err != nil {
		t.Skip("git metadata unavailable; tag-link guard runs in repository checkouts")
	}

	cmd := exec.Command("git", "tag", "--list")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list repository tags: %v", err)
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Fields(string(out)) {
		tags[tag] = struct{}{}
	}

	changelog := readRepoFile(t, "CHANGELOG.md")
	compareLines := regexp.MustCompile(`(?m)^\[[^]]+\]: .*?/compare/.*$`).FindAllString(changelog, -1)
	links := regexp.MustCompile(`(?m)^\[([^]]+)\]: https://github\.com/dimaggi-ai/tool-guard-core/compare/([^\s]+)\.\.\.([^\s]+)$`).FindAllStringSubmatch(changelog, -1)
	if len(links) == 0 {
		t.Fatal("CHANGELOG.md has no release comparison links")
	}
	if len(links) != len(compareLines) {
		t.Fatalf("CHANGELOG.md has %d compare links but only %d use the required shape", len(compareLines), len(links))
	}
	for _, link := range links {
		label, from, to := link[1], link[2], link[3]
		if label != "Unreleased" && to != "v"+label {
			t.Errorf("CHANGELOG link [%s] ends at %s, want v%s", label, to, label)
		}
		for _, ref := range []string{from, to} {
			if ref == "HEAD" && label == "Unreleased" {
				continue
			}
			if _, ok := tags[ref]; !ok {
				t.Errorf("CHANGELOG link [%s] references missing tag %s", label, ref)
			}
		}
	}

	releaseLinks := regexp.MustCompile(`(?m)^\[([^]]+)\]: https://github\.com/dimaggi-ai/tool-guard-core/releases/tag/([^\s]+)$`).FindAllStringSubmatch(changelog, -1)
	for _, link := range releaseLinks {
		if link[2] != "v"+link[1] {
			t.Errorf("CHANGELOG link [%s] targets %s, want v%s", link[1], link[2], link[1])
		}
		if _, ok := tags[link[2]]; !ok {
			t.Errorf("CHANGELOG link [%s] references missing tag %s", link[1], link[2])
		}
	}
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	pathParts := append([]string{"..", ".."}, parts...)
	b, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

func regexpMatches(t *testing.T, pattern, input string) []string {
	t.Helper()
	matches := regexp.MustCompile(pattern).FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		t.Fatalf("pattern %q matched no values", pattern)
	}
	values := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		value := match[1]
		if _, duplicate := seen[value]; duplicate {
			t.Fatalf("value %q is documented more than once", value)
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func commandDispatchNames(t *testing.T, filename string) []string {
	t.Helper()
	file := parseGoFile(t, filename)
	var commands []string
	ast.Inspect(file, func(node ast.Node) bool {
		switchStmt, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		ident, ok := switchStmt.Tag.(*ast.Ident)
		if !ok || ident.Name != "verb" {
			return true
		}
		for _, statement := range switchStmt.Body.List {
			clause := statement.(*ast.CaseClause)
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				name, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote command name %s: %v", literal.Value, err)
				}
				if strings.HasPrefix(name, "-") || name == "help" {
					continue
				}
				commands = append(commands, name)
			}
		}
		return false
	})
	if len(commands) == 0 {
		t.Fatal("found no commands in switch verb")
	}
	return commands
}

func lintRuleNames(t *testing.T, filename string, functionNames ...string) []string {
	t.Helper()
	file := parseGoFile(t, filename)
	wanted := make(map[string]struct{}, len(functionNames))
	for _, name := range functionNames {
		wanted[name] = struct{}{}
	}
	rules := make(map[string]struct{})
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := wanted[function.Name.Name]; !ok {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			pair, ok := node.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, keyOK := pair.Key.(*ast.Ident)
			value, valueOK := pair.Value.(*ast.BasicLit)
			if !keyOK || key.Name != "Rule" || !valueOK || value.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(value.Value)
			if err != nil {
				t.Fatalf("unquote lint rule %s: %v", value.Value, err)
			}
			rules[name] = struct{}{}
			return true
		})
	}
	if len(rules) == 0 {
		t.Fatal("found no lint rule literals")
	}
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func conditionClassifierNames(t *testing.T, filename string) []string {
	t.Helper()
	file := parseGoFile(t, filename)
	var names []string
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Condition" {
			return true
		}
		structure, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			t.Fatal("domain.Condition is not a struct")
		}
		for _, field := range structure.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Fatalf("unquote Condition field tag %s: %v", field.Tag.Value, err)
			}
			jsonName := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
			if strings.HasSuffix(jsonName, "_classify") {
				names = append(names, jsonName)
			}
		}
		return false
	})
	if len(names) == 0 {
		t.Fatal("found no classifier fields on domain.Condition")
	}
	sort.Strings(names)
	return names
}

func parseGoFile(t *testing.T, filename string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	return file
}
