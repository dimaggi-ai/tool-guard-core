package main

// These tests close holes in support_claims_test.go that let an unverified
// harness claim pass: an alias matched a row on any shared word, the alias
// list was not tied to the matrix, the claim scan read one line at a time
// with a short verb list, and the version scan pooled every harness.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestHarnessAliasNeedsEveryToken(t *testing.T) {
	row := map[string]string{"OpenAI Codex CLI": "verified"}
	if !aliasIsVerified(row, "codex-cli") {
		t.Errorf("codex-cli must match the row OpenAI Codex CLI")
	}
	for _, other := range []string{"gemini-cli", "antigravity-cli", "claude code"} {
		if aliasIsVerified(row, other) {
			t.Errorf("%q must not be verified by the row OpenAI Codex CLI: sharing one word is not a match", other)
		}
	}
}

// rowCoversAlias reports whether every token of alias is in the row name.
func rowCoversAlias(row, alias string) bool {
	have := tokens(row)
	want := tokens(alias)
	return len(want) > 0 && !slices.ContainsFunc(want, func(tk string) bool { return !slices.Contains(have, tk) })
}

func TestEveryHarnessAliasResolvesToAMatrixRow(t *testing.T) {
	rows := loadSupportMatrix(t)
	for _, alias := range harnessAliases {
		found := false
		for name := range rows {
			found = found || rowCoversAlias(name, alias)
		}
		if !found {
			t.Errorf("alias %q matches no row of docs/support-matrix.md, so a claim about it is never checked against a status", alias)
		}
	}
	for name := range rows {
		found := false
		for _, alias := range harnessAliases {
			found = found || rowCoversAlias(name, alias)
		}
		if !found {
			t.Errorf("matrix row %q has no entry in harnessAliases, so the docs are never scanned for it", name)
		}
	}
}

// claimDocFiles lists every file whose text can carry a harness claim.
func claimDocFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := []string{filepath.Join(root, "README.md"), filepath.Join(root, "CHANGELOG.md")}
	for _, pattern := range []string{
		filepath.Join(root, "docs", "*.md"),
		filepath.Join(root, "examples", "*", "README.md"),
		filepath.Join(root, "examples", "coding-agent-guard", "*.sh"),
		filepath.Join(root, "examples", "coding-agent-guard", "hooks", "*.sh"),
		filepath.Join(root, "examples", "coding-agent-guard", "config", "*.json"),
		filepath.Join(root, "policies", "*.md"),
	} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		files = append(files, found...)
	}
	out := files[:0]
	for _, f := range files {
		if !strings.HasSuffix(f, "support-matrix.md") {
			out = append(out, f)
		}
	}
	return out
}

var wideClaimRe = regexp.MustCompile(`(?i)\b(gate[sd]?|gating|support(s|ed|ing)?|wire[sd]?|wiring|work(s|ed|ing)?\s+(with|on|in|for)|compatible|integrat(e|es|ed|ion|ions)|verified|guard(s|ed|ing)?|protect(s|ed|ing)?|enforce[sd]?|enforcement|block(s|ed|ing)?|stop(s|ped|ping)?|honou?r(s|ed|ing)?|cover(s|ed|age)?)\b`)

var pathLikeRe = regexp.MustCompile(`[~.]?(/[A-Za-z0-9_.\-]+)+/?`)

// TestDocsHarnessClaimsWideScan reads two lines at a time, because a claim
// often has its harness name on one line and its verb on the next. Path-like
// text is removed first: ~/.gemini/config/hooks.json is a location, not a
// claim. A unit that contains the word MCP is skipped: MCP clients are a
// different integration from PreToolUse hooks and the matrix does not cover
// them.
func TestDocsHarnessClaimsWideScan(t *testing.T) {
	rows := loadSupportMatrix(t)
	for _, f := range claimDocFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		lines := strings.Split(string(raw), "\n")
		for i := range lines {
			unit := lines[i]
			if i+1 < len(lines) {
				unit += " " + lines[i+1]
			}
			if strings.Contains(unit, "MCP") {
				continue
			}
			unit = pathLikeRe.ReplaceAllString(unit, " ")
			if !wideClaimRe.MatchString(unit) {
				continue
			}
			lower := strings.ToLower(unit)
			for _, alias := range harnessAliases {
				if strings.Contains(lower, alias) && !aliasIsVerified(rows, alias) {
					t.Errorf("%s:%d states something about %q, which is not verified in docs/support-matrix.md: %s",
						f, i+1, alias, strings.TrimSpace(lines[i]))
				}
			}
		}
	}
}

// TestDocsVersionsArePerHarness fails when a file names a harness next to a
// version that no real-install capture and no verified row records for that
// same harness. A version recorded for another harness does not count.
func TestDocsVersionsArePerHarness(t *testing.T) {
	rows := loadSupportMatrix(t)
	known := map[string]map[string]bool{}
	for _, alias := range harnessAliases {
		known[alias] = map[string]bool{}
		for _, c := range loadHookCases(t) {
			if c.Capture.CapturedFrom == "real install" && rowCoversAlias(c.Harness, alias) {
				known[alias][c.HarnessVersion] = true
			}
		}
		for name, status := range rows {
			if status == "verified" && rowCoversAlias(name, alias) {
				known[alias][matrixVersion(loadMatrixLine(t, name))] = true
			}
		}
	}
	for _, f := range claimDocFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "or newer") || strings.Contains(lower, "or later") {
				continue // a minimum version, not a measured one
			}
			for _, loc := range versionRe.FindAllStringIndex(line, -1) {
				v := line[loc[0]:loc[1]]
				alias := nearestAliasBefore(lower, loc[0])
				if alias == "" || isDateLike(v) || known[alias][v] {
					continue
				}
				t.Errorf("%s:%d names %s at version %s, which no real-install capture and no verified row records for that harness: %s",
					f, i+1, alias, v, strings.TrimSpace(line))
			}
		}
	}
}

// nearestAliasBefore returns the harness alias that starts closest before
// byte offset pos, when it starts at most 60 bytes before pos. A version is
// read as belonging to the harness named just before it.
func nearestAliasBefore(lower string, pos int) string {
	best, bestAt := "", -1
	for _, alias := range harnessAliases {
		at := strings.LastIndex(lower[:pos], alias)
		if at > bestAt {
			best, bestAt = alias, at
		}
	}
	if bestAt < 0 || pos-bestAt > 60 {
		return ""
	}
	return best
}

// TestHookDialectFlagEdgeCases pins three behaviours no test covered: an
// explicit claude dialect wins over an Antigravity payload, the explicit value
// auto detects the payload, and an unknown value behaves as auto.
func TestHookDialectFlagEdgeCases(t *testing.T) {
	agy := `{"toolCall":{"name":"write_file","args":{"Path":"/x/AGENTS.md","Content":"package main"}}}`
	policies := filepath.Join("..", "..", "policies")
	out, _ := runHookStr(t, agy, "-policy-dir", policies, "-mode", "enforcement", "-dialect", "claude")
	if !strings.Contains(out, "hookSpecificOutput") {
		t.Errorf("-dialect claude must emit the Claude shape for an Antigravity payload, got: %s", out)
	}
	for _, value := range []string{"auto", "no-such-dialect"} {
		out, _ = runHookStr(t, agy, "-policy-dir", policies, "-mode", "enforcement", "-dialect", value)
		if strings.Contains(out, "hookSpecificOutput") || !strings.Contains(out, `"decision"`) {
			t.Errorf("-dialect %s must detect the Antigravity payload and emit the top-level shape, got: %s", value, out)
		}
	}
}
