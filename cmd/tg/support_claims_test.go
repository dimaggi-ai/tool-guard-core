package main

// Support claims are only as good as the captures behind them. These tests
// keep docs/support-matrix.md, the hook conformance corpus and the prose in
// README.md and docs/ from drifting apart: a harness may be described as
// gated or supported only if a real-install capture of it is replayed by
// TestHookConformance and recorded as verified in the matrix.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func loadSupportMatrix(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "support-matrix.md"))
	if err != nil {
		t.Fatalf("read docs/support-matrix.md: %v", err)
	}
	rows := map[string]string{}
	// Only the support table counts. The file carries other tables (which
	// decisions each harness honoured, how to reproduce a claim), and a row in
	// one of those is not a support status.
	inSupportTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inSupportTable = false
			continue
		}
		if strings.HasPrefix(line, "| Harness | Version | Status |") {
			inSupportTable = true
			continue
		}
		if !inSupportTable {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 3 {
			continue
		}
		name := strings.TrimSpace(cells[0])
		status := strings.TrimSpace(cells[2])
		if name == "Harness" || strings.HasPrefix(name, "---") || name == "" {
			continue
		}
		if status == "" {
			t.Errorf("matrix row %q has no status", name)
			continue
		}
		rows[name] = status
	}
	if len(rows) == 0 {
		t.Fatal("docs/support-matrix.md has no parseable rows")
	}
	return rows
}

var tokenRe = regexp.MustCompile(`[a-z0-9]+`)

func tokens(s string) []string {
	out := tokenRe.FindAllString(strings.ToLower(s), -1)
	slices.Sort(out)
	return out
}

func matrixRow(rows map[string]string, harness string) (string, string, bool) {
	// A matrix row may carry more naming than the corpus key ("OpenAI Codex
	// CLI" vs "codex-cli"), so the row must contain every corpus token.
	want := tokens(harness)
	for name, status := range rows {
		have := tokens(name)
		if slices.ContainsFunc(want, func(tk string) bool { return slices.Contains(have, tk) }) &&
			countContains(have, want) == len(want) {
			return name, status, true
		}
	}
	return "", "", false
}

func countContains(have, want []string) int {
	n := 0
	for _, tk := range want {
		if slices.Contains(have, tk) {
			n++
		}
	}
	return n
}

func TestSupportMatrixMatchesCorpus(t *testing.T) {
	rows := loadSupportMatrix(t)
	for _, c := range loadHookCases(t) {
		if c.Capture.CapturedFrom != "real install" {
			continue
		}
		name, status, ok := matrixRow(rows, c.Harness)
		if !ok {
			t.Errorf("corpus case %s captured from %s has no row in docs/support-matrix.md", c.Name, c.Harness)
			continue
		}
		if status != "verified" {
			t.Errorf("corpus case %s replays a real %s capture but the matrix marks %q as %q", c.Name, c.Harness, name, status)
		}
		if !slices.Contains(matrixVersions(loadMatrixLine(t, name)), c.HarnessVersion) {
			t.Errorf("matrix row for %s does not name version %s used by case %s", name, c.HarnessVersion, c.Name)
		}
	}
}

func loadMatrixLine(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "support-matrix.md"))
	if err != nil {
		t.Fatalf("read matrix: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| "+name+" ") || strings.HasPrefix(strings.TrimSpace(line), "| "+name+"|") {
			return line
		}
	}
	t.Fatalf("no matrix line for %q", name)
	return ""
}

var harnessAliases = []string{
	"claude code", "codex", "antigravity", "gemini", "cursor", "copilot",
	"windsurf", "continue.dev", "cline", "aider", "opencode",
}

var claimRe = regexp.MustCompile(`(?i)\b(gate|gates|gating|support|supports|supported|wires the hooks)\b`)

// TestDocsHarnessClaimsAreVerified fails when README.md or docs/*.md asserts
// that Tool Guard gates or supports a harness that is not verified in
// docs/support-matrix.md.
func TestDocsHarnessClaimsAreVerified(t *testing.T) {
	rows := loadSupportMatrix(t)
	verified := map[string]bool{}
	for name, status := range rows {
		if status == "verified" {
			verified[name] = true
		}
	}
	// Everything a user or an operator reads, not only the README. Measured
	// 2026-11-09: a false "now supports Cursor, Windsurf and Gemini CLI" line
	// planted in CHANGELOG.md and in the example README passed the whole suite,
	// as did a false installer echo, because neither file was scanned.
	files := []string{"../../README.md", "../../CHANGELOG.md"}
	paths, _ := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	files = append(files, paths...)
	examples, _ := filepath.Glob(filepath.Join("..", "..", "examples", "*", "README.md"))
	files = append(files, examples...)
	files = append(files, filepath.Join("..", "..", "examples", "coding-agent-guard", "install.sh"))
	cfgs, _ := filepath.Glob(filepath.Join("..", "..", "examples", "coding-agent-guard", "config", "*.json"))
	files = append(files, cfgs...)
	for _, f := range files {
		if strings.HasSuffix(f, "support-matrix.md") {
			continue // the matrix itself states what is not supported
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if !claimRe.MatchString(line) {
				continue
			}
			lower := strings.ToLower(line)
			for _, alias := range harnessAliases {
				if !strings.Contains(lower, alias) {
					continue
				}
				if !aliasIsVerified(rows, alias) {
					t.Errorf("%s:%d claims something about %q, which is not verified in docs/support-matrix.md: %s",
						f, i+1, alias, strings.TrimSpace(line))
				}
			}
		}
	}
}

// aliasIsVerified resolves a harness named in prose to a matrix row and checks
// that row's status. It previously compared the alias against a hard-coded list
// of three names, which meant the matrix could mark a harness "not supported"
// and delete its captures while the prose kept claiming support — the check
// tested its own constant, not the evidence.
func aliasIsVerified(rows map[string]string, alias string) bool {
	want := tokens(alias)
	if len(want) == 0 {
		return false
	}
	for name, status := range rows {
		if status != "verified" {
			continue
		}
		have := tokens(name)
		// Every token of the alias must be in the row name. "codex" matches
		// "OpenAI Codex CLI". "gemini-cli" does not, although both contain "cli".
		if !slices.ContainsFunc(want, func(tk string) bool { return !slices.Contains(have, tk) }) {
			return true
		}
	}
	return false
}

// TestVerifiedMatrixRowsHaveCorpusSupport closes the other direction. The
// original check only ran corpus -> matrix, so deleting every capture for a
// harness left its "verified" row standing and the suite green.
func TestVerifiedMatrixRowsHaveCorpusSupport(t *testing.T) {
	rows := loadSupportMatrix(t)
	cases := loadHookCases(t)
	for name, status := range rows {
		if status != "verified" {
			continue
		}
		line := loadMatrixLine(t, name)
		versions := matrixVersions(line)
		if len(versions) == 0 {
			t.Errorf("matrix row %q names no version, so its claim cannot be reproduced or re-checked", name)
			continue
		}
		captured := map[string]bool{}
		for _, c := range cases {
			if c.Capture.CapturedFrom != "real install" {
				continue
			}
			if aliasIsVerified(map[string]string{name: "verified"}, c.Harness) {
				captured[c.HarnessVersion] = true
			}
		}
		for _, v := range versions {
			if !captured[v] {
				t.Errorf("matrix row %q claims version %s but the corpus holds no real-install capture at that version; either capture it or drop the version from the row", name, v)
			}
		}
	}
}

// matrixVersions pulls every version out of a support-table row's version cell.
// A row may legitimately list more than one version ("2.1.316, 2.1.321") when
// captures exist at each: the CLI updates itself, so the measured set grows over
// time and a single-version cell would force either a stale claim or a false
// failure.
func matrixVersions(line string) []string {
	cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	if len(cells) < 2 {
		return nil
	}
	re := regexp.MustCompile(`[0-9]+(?:\.[0-9A-Za-z]+)+`)
	return re.FindAllString(cells[1], -1)
}

func matrixVersion(line string) string {
	vs := matrixVersions(line)
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// TestDocsVersionsMatchVerifiedRows rejects a claim that names a harness at a
// version no capture exists for. Mutations that named "Codex CLI 9.9.9" passed
// the earlier suite because only harness names were checked, never versions.
func TestDocsVersionsMatchVerifiedRows(t *testing.T) {
	rows := loadSupportMatrix(t)
	cases := loadHookCases(t)
	known := map[string]bool{}
	for _, c := range cases {
		if c.Capture.CapturedFrom == "real install" {
			known[c.HarnessVersion] = true
		}
	}
	for name, status := range rows {
		if v := matrixVersion(loadMatrixLine(t, name)); v != "" && status == "verified" {
			known[v] = true
		}
	}
	files := []string{"../../README.md", "../../CHANGELOG.md"}
	paths, _ := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	files = append(files, paths...)
	examples, _ := filepath.Glob(filepath.Join("..", "..", "examples", "*", "README.md"))
	files = append(files, examples...)
	for _, f := range files {
		if strings.HasSuffix(f, "support-matrix.md") {
			// The matrix carries its own statuses; unverified rows there are the
			// honest record, not a claim. They are checked by
			// TestVerifiedMatrixRowsHaveCorpusSupport instead.
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			lower := strings.ToLower(line)
			if !claimRe.MatchString(line) {
				continue
			}
			// A stated floor ("2.1.139 or newer") and an explicit refusal are not
			// claims of tested support; flagging them pushed the suite toward
			// deleting useful information rather toward honesty.
			if strings.Contains(lower, "or newer") || strings.Contains(lower, "or later") ||
				strings.Contains(lower, "not supported") || strings.Contains(lower, "cannot verify") {
				continue
			}
			for _, alias := range harnessAliases {
				if !strings.Contains(lower, alias) {
					continue
				}
				for _, m := range versionRe.FindAllString(line, -1) {
					if isDateLike(m) || known[m] {
						continue
					}
					if mentionsHarnessVersion(line, alias, m) {
						t.Errorf("%s:%d names %s at version %s, which no real-install capture covers: %s",
							f, i+1, alias, m, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}

var versionRe = regexp.MustCompile(`\b\d+\.\d+(\.\d+)?\b`)

func isDateLike(v string) bool {
	return strings.HasPrefix(v, "202") || strings.HasPrefix(v, "2026")
}

// mentionsHarnessVersion keeps the check honest: it fires only when a version
// appears in the same clause as the harness name, not for any number on a line.
func mentionsHarnessVersion(line, alias, version string) bool {
	lower := strings.ToLower(line)
	ai := strings.Index(lower, alias)
	if ai < 0 {
		return false
	}
	vi := strings.Index(line, version)
	if vi < 0 {
		return false
	}
	return absInt(vi-ai) <= 60
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// TestHookHonoursExplicitDialectFlags exists because nothing in the suite ever
// passed -dialect: a regression that made auto-detection win over an explicit
// operator choice would not have been caught.
func TestHookHonoursExplicitDialectFlags(t *testing.T) {
	agy := `{"toolCall":{"name":"write_file","args":{"Path":"/x/AGENTS.md","Content":"package main"}}}`
	claude := `{"tool_name":"Write","tool_input":{"file_path":"/x/AGENTS.md","content":"x"}}`
	policies := ".." + "/" + ".." + "/policies"

	out, _ := runHookStr(t, agy, "-policy-dir", policies, "-mode", "enforcement", "-dialect", "antigravity")
	if !strings.Contains(out, `"decision"`) || strings.Contains(out, "hookSpecificOutput") {
		t.Errorf("-dialect antigravity must emit the top-level Antigravity shape, got: %s", out)
	}
	out, _ = runHookStr(t, claude, "-policy-dir", policies, "-mode", "enforcement", "-dialect", "claude")
	if !strings.Contains(out, "hookSpecificOutput") {
		t.Errorf("-dialect claude must emit the Claude shape, got: %s", out)
	}
	// Explicit must beat auto-detection: that override is the documented
	// operator control, and no test exercised it before.
	out, _ = runHookStr(t, claude, "-policy-dir", policies, "-mode", "enforcement", "-dialect", "antigravity")
	if strings.Contains(out, "hookSpecificOutput") {
		t.Errorf("explicit -dialect antigravity must override a Claude-shaped payload, got: %s", out)
	}
}

// TestSupportMatrixTableIsWellFormed catches a silent markdown defect: a row
// with fewer cells than the header drops its trailing column without any
// rendering that a reader would notice. A caught-once defect, 2026-11-09.
func TestSupportMatrixTableIsWellFormed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "support-matrix.md"))
	if err != nil {
		t.Fatalf("read matrix: %v", err)
	}
	inTable := false
	headerCells := 0
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if !inTable {
			inTable, headerCells = true, len(cells)
			continue
		}
		if len(cells) != headerCells {
			t.Errorf("support-matrix.md line %d has %d cells, the header has %d: %s", i+1, len(cells), headerCells, trimmed)
		}
	}
}

// TestInstallerOutputMakesNoUnmeasuredPromise keeps the installer's own stdout
// inside the measured claim boundary. Installer text is the one user-facing
// surface that used to suggest an escalation would visibly intervene, which the
// release run does not show for every harness.
func TestInstallerOutputMakesNoUnmeasuredPromise(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "coding-agent-guard", "install.sh"))
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	text := string(raw)
	for _, banned := range []string{"watch Tool Guard step in", "and watch Tool Guard"} {
		if strings.Contains(text, banned) {
			t.Errorf("installer promises escalation behaviour (%q); docs/support-matrix.md records what each harness did with an escalation", banned)
		}
	}
	for _, required := range []string{"Codex will not run this hook until", "trust", "verify-harnesses.sh"} {
		if !strings.Contains(text, required) {
			t.Errorf("installer no longer states %q, which a measured run showed an operator needs to know", required)
		}
	}
}
