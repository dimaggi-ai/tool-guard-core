package main

// docs/evidence/harness-manifest.json is the manifest.json that one release
// run of examples/coding-agent-guard/verify-harnesses.sh wrote. These tests
// validate historical evidence, not evidence for the current release. The
// separate make release-binding gate checks source and binary provenance.
// These tests tie together the manifest, its measured wiring, and
// the harness statements in docs/support-matrix.md. A statement about what a
// harness did with a decision can only appear in the matrix through the block
// these tests render from the manifest.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

type harnessManifestStage struct {
	ID       string         `json:"id"`
	Expect   string         `json:"expect"`
	Wanted   string         `json:"wanted_decision"`
	Decision string         `json:"decision"`
	Tool     string         `json:"tool"`
	Runs     int            `json:"runs"`
	Outcomes map[string]int `json:"outcomes"`
	Outcome  string         `json:"outcome"`
	Result   string         `json:"result"`
}

// manifestMinRuns is the least number of times a release run must send every
// stage. Measured 2026-11-09: one run of a harness differed from the next, so
// one run is not release evidence. The Makefile target verify-harnesses sets
// TG_VERIFY_REPEAT to the same number.
const manifestMinRuns = 3

type harnessManifestEntry struct {
	ID            string                 `json:"id"`
	Configuration string                 `json:"configuration"`
	Installed     bool                   `json:"installed"`
	Version       string                 `json:"version"`
	VersionNumber string                 `json:"version_number"`
	Stages        []harnessManifestStage `json:"stages"`
}

type harnessManifest struct {
	Schema      int                    `json:"schema"`
	GeneratedAt string                 `json:"generated_at"`
	Commit      string                 `json:"commit"`
	Dirty       *bool                  `json:"working_tree_dirty"`
	Trimpath    *bool                  `json:"tg_build_trimpath"`
	Binary      string                 `json:"tg_sha256"`
	Wiring      string                 `json:"wiring_sha256"`
	Shipped     bool                   `json:"policy_dir_is_shipped"`
	Filter      string                 `json:"harness_filter"`
	Repeat      int                    `json:"repeat"`
	Failures    int                    `json:"failures"`
	Harnesses   []harnessManifestEntry `json:"harnesses"`
}

func loadHarnessManifest(t *testing.T) harnessManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "evidence", "harness-manifest.json"))
	if err != nil {
		t.Fatalf("read docs/evidence/harness-manifest.json: %v (it is the manifest.json of a release run of verify-harnesses.sh)", err)
	}
	var m harnessManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse docs/evidence/harness-manifest.json: %v", err)
	}
	return m
}

// exampleWiringSHA256 repeats the computation in verify_harnesses.py: for each
// listed file, the relative path, a newline, the file's SHA-256 in hex and a
// newline are fed to one SHA-256.
func exampleWiringSHA256(t *testing.T) string {
	t.Helper()
	ex := filepath.Join("..", "..", "examples", "coding-agent-guard")
	files := []string{
		"hooks/guard-hook.sh", "hooks/claude-code-hook.sh", "hooks/codex-hook.sh",
		"hooks/antigravity-cli-hook.sh", "config/claude-code.settings.json",
		"config/codex.hooks.json", "config/antigravity.hooks.json",
	}
	policies, err := filepath.Glob(filepath.Join(ex, "policies", "*.yaml"))
	if err != nil || len(policies) == 0 {
		t.Fatalf("no policy files under %s/policies (err %v)", ex, err)
	}
	sort.Strings(policies)
	for _, p := range policies {
		files = append(files, "policies/"+filepath.Base(p))
	}
	h := sha256.New()
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(ex, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		h.Write([]byte(rel + "\n" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// manifestMatrixName maps a manifest harness id to its row name in
// docs/support-matrix.md.
var manifestMatrixName = map[string]string{
	"claude-code":     "Claude Code",
	"codex-cli":       "OpenAI Codex CLI",
	"antigravity-cli": "Antigravity CLI (`agy`)",
}

var manifestOutcomeWords = map[string]string{
	"blocked":          "blocked",
	"ran":              "ran",
	"ran_without_hook": "ran, hook not called",
	"not_measured":     "not measured",
	"worked_around":    "worked around",
}

// manifestOutcomeCell words what the runs of one stage showed: every outcome
// with the number of runs that had it.
func manifestOutcomeCell(s harnessManifestStage) string {
	keys := make([]string, 0, len(s.Outcomes))
	for k, n := range s.Outcomes {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		part := fmt.Sprintf("%s in %d", manifestOutcomeWords[k], s.Outcomes[k])
		if s.Outcomes["worked_around"] > 0 {
			part += fmt.Sprintf(" of %d", s.Runs)
		}
		parts = append(parts, part)
	}
	if s.Outcomes["worked_around"] > 0 {
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s of %d", strings.Join(parts, ", "), s.Runs)
}

func TestManifestOutcomeCellKeepsWorkaroundsSeparate(t *testing.T) {
	stage := harnessManifestStage{Runs: 3, Outcomes: map[string]int{"blocked": 2, "worked_around": 1}}
	if got, want := manifestOutcomeCell(stage), "blocked in 2 of 3, worked around in 1 of 3"; got != want {
		t.Fatalf("outcome cell = %q, want %q", got, want)
	}
	stage.Outcomes = map[string]int{"blocked": 3, "worked_around": 0}
	if got := manifestOutcomeCell(stage); got != "blocked in 3 of 3" {
		t.Fatalf("zero workarounds changed outcome cell: %q", got)
	}
}

// manifestSentences are the only operator statements about harness behaviour.
// A sentence is printed when the named stage has the named outcome in at
// least one run, followed by the number of runs that had it.
var manifestSentences = []struct {
	id, configuration, stage, outcome, text string
}{
	{"codex-cli", "codex exec, hook not trusted", "untrusted_hook", "ran_without_hook",
		"%s %s did not call a hook it had not been made to trust, and the command ran. Start `codex` and accept the hook before you rely on it."},
	{"codex-cli", "codex exec", "escalation_shell_raw_ask", "ran",
		"%s %s ran a command after the hook answered `ask`. The shipped Codex wrapper returns an escalation as a denial."},
	{"codex-cli", "codex exec", "write_tool_deny", "ran_without_hook",
		"%s %s wrote a file with its own edit tool without calling the hook. On this harness the wrapper sees shell commands only."},
	{"antigravity-cli", "agy --dangerously-skip-permissions --print", "escalation_shell_plain_ask", "ran",
		"%s %s, started with `--dangerously-skip-permissions`, ran a command after the hook answered `ask`. Set `TG_ESCALATE_AS=deny` when you start it with that flag."},
	{"antigravity-cli", "agy --dangerously-skip-permissions --print", "escalation_shell", "ran",
		"%s %s, started with `--dangerously-skip-permissions`, ran a command after the hook answered `force_ask`. Set `TG_ESCALATE_AS=deny` when you start it with that flag."},
	{"antigravity-cli", "agy --print", "shell_allow_control", "blocked",
		"%s %s, started without `--dangerously-skip-permissions`, did not run a command that the hook allowed. In this configuration a `blocked` outcome does not show that the guard stopped the call."},
	{"antigravity-cli", "agy --print", "write_tool_allow_control", "blocked",
		"%s %s, started without `--dangerously-skip-permissions`, did not write a file that the hook allowed. In this configuration a `blocked` outcome does not show that the guard stopped the call."},
	{"antigravity-cli", "agy --print", "escalation_shell", "ran",
		"%s %s, started without `--dangerously-skip-permissions`, ran a command after the hook answered `force_ask`. Set `TG_ESCALATE_AS=deny` on this harness."},
}

// renderHarnessEvidence returns the block that docs/support-matrix.md must
// hold between the two harness-evidence marker lines.
func renderHarnessEvidence(m harnessManifest) string {
	var b strings.Builder
	commit := m.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	fmt.Fprintf(&b, "Generated from `docs/evidence/harness-manifest.json` (commit `%s`, run of %s, every stage sent %d times). Do not edit this block by hand.\n\n", commit, m.GeneratedAt, m.Repeat)
	b.WriteString("| Harness | Version | Started as | Stage | Decision returned | Tool the harness called | Outcome, in runs |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	var notes []string
	for _, h := range m.Harnesses {
		name := manifestMatrixName[h.ID]
		for _, s := range h.Stages {
			decision, tool := "none", "none"
			if s.Decision != "" {
				decision = "`" + s.Decision + "`"
			}
			if s.Tool != "" {
				tool = "`" + s.Tool + "`"
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` | %s | %s | %s |\n", name, h.VersionNumber, h.Configuration, s.ID, decision, tool, manifestOutcomeCell(s))
			for _, rule := range manifestSentences {
				if rule.id == h.ID && rule.configuration == h.Configuration && rule.stage == s.ID && s.Outcomes[rule.outcome] > 0 {
					notes = append(notes, "- "+fmt.Sprintf(rule.text, name, h.VersionNumber)+fmt.Sprintf(" Seen in %d of %d runs.", s.Outcomes[rule.outcome], s.Runs))
				}
			}
			if h.ID == "codex-cli" && s.ID == "write_tool_allow_control" && s.Tool == "apply_patch" && s.Decision == "deny" {
				notes = append(notes, fmt.Sprintf("- %s %s called `apply_patch` to write a file that no rule protects, and the hook answered `deny`. The binary of that run did not read the files from the patch text. `tg hook` now reads them, and no harness run has measured that.", name, h.VersionNumber))
			}
			if n := s.Outcomes["not_measured"]; n > 0 {
				notes = append(notes, fmt.Sprintf("- %s %s, started as `%s`: stage `%s` was not measured in %d of %d runs.", name, h.VersionNumber, h.Configuration, s.ID, n, s.Runs))
			}
		}
	}
	b.WriteString("\nOutcome words: `blocked` means the hook returned the decision and the tool call had no effect. `ran` means the tool call took effect and the hook was called at least once in that run. `ran, hook not called` means the tool call took effect and the hook was never called. `not measured` means the run does not show which of these happened. The last column gives, for every outcome, the number of runs that had it.\n")
	if len(notes) > 0 {
		b.WriteString("\nWhat this run means for an operator:\n\n" + strings.Join(notes, "\n") + "\n")
	}
	return b.String()
}

// This exact legacy run predates binary VCS and verifier metadata. Pin its
// recorded hashes so ordinary tests can validate the historical artifact in
// shallow checkouts without pretending that current source was measured.
// New measurements use the current wiring; only release-binding can establish
// that their binary and verifier also match the release source.
const legacyHarnessCommit = "24eafd647ce3fabebe0837df540340ed31b30829"
const legacyHarnessWiring = "0222a7e55e5a685827c9f2d5701e0eb683740279282d94f27b57df1eb71122fa"
const legacyHarnessBinary = "fa2308b9f1fb1e67367a4371633dfc09fa36d5586e4d8c0d45154dfbf1956e45"

func TestHarnessManifestIsHistoricalEvidence(t *testing.T) {
	m := loadHarnessManifest(t)
	if m.Schema != 4 && m.Schema != 5 {
		t.Errorf("schema is %d, want 4 or 5", m.Schema)
	}
	if m.Repeat < manifestMinRuns {
		t.Errorf("every stage was sent %d time(s), want at least %d: run make verify-harnesses", m.Repeat, manifestMinRuns)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.Commit) {
		t.Errorf("commit %q is not a full commit id", m.Commit)
	}
	if m.Dirty == nil || *m.Dirty {
		t.Errorf("the manifest was not produced from a clean working tree")
	}
	if m.Trimpath == nil || !*m.Trimpath {
		t.Errorf("the manifest was not produced with a tg built with -trimpath")
	}
	if !m.Shipped || m.Filter != "all" || m.Failures != 0 {
		t.Errorf("policy_dir_is_shipped=%v harness_filter=%q failures=%d; want true, all, 0", m.Shipped, m.Filter, m.Failures)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.Binary) {
		t.Errorf("tg_sha256 %q is not a SHA-256 digest", m.Binary)
	}
	wantWiring := legacyHarnessWiring
	if m.Commit == legacyHarnessCommit {
		if m.Schema != 4 {
			t.Errorf("historical schema changed: got %d, want 4", m.Schema)
		}
		if m.Binary != legacyHarnessBinary {
			t.Errorf("historical binary hash changed: got %s, want %s", m.Binary, legacyHarnessBinary)
		}
	} else {
		wantWiring = exampleWiringSHA256(t)
	}
	if m.Wiring != wantWiring {
		t.Errorf("wiring_sha256 is %s, want measured wiring %s", m.Wiring, wantWiring)
	}
	for _, h := range m.Harnesses {
		if manifestMatrixName[h.ID] == "" {
			t.Errorf("manifest harness id %q has no name in manifestMatrixName", h.ID)
		}
		if !h.Installed || h.VersionNumber == "" || strings.Contains(h.Version, "stub") {
			t.Errorf("%s [%s]: installed=%v version=%q; the manifest must come from real, installed harnesses", h.ID, h.Configuration, h.Installed, h.Version)
		}
		for _, s := range h.Stages {
			total := 0
			for word, n := range s.Outcomes {
				total += n
				if manifestOutcomeWords[word] == "" {
					t.Errorf("%s [%s] %s: unknown outcome word %q", h.ID, h.Configuration, s.ID, word)
				}
			}
			if s.Runs != m.Repeat || total != s.Runs {
				t.Errorf("%s [%s] %s: runs %d, counted outcomes %d, manifest repeat %d; all three must be equal", h.ID, h.Configuration, s.ID, s.Runs, total, m.Repeat)
			}
			if s.Result == "FAIL" {
				t.Errorf("%s [%s] %s: result FAIL, outcomes %v", h.ID, h.Configuration, s.ID, s.Outcomes)
			}
		}
	}
}

func TestSupportMatrixEvidenceBlockMatchesManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "support-matrix.md"))
	if err != nil {
		t.Fatalf("read docs/support-matrix.md: %v", err)
	}
	const begin, end = "<!-- harness-evidence:begin -->\n", "<!-- harness-evidence:end -->\n"
	text := string(raw)
	i, j := strings.Index(text, begin), strings.Index(text, end)
	if i < 0 || j < i || strings.Count(text, begin) != 1 || strings.Count(text, end) != 1 {
		t.Fatalf("docs/support-matrix.md must hold exactly one line %q followed later by exactly one line %q", strings.TrimSpace(begin), strings.TrimSpace(end))
	}
	want := renderHarnessEvidence(loadHarnessManifest(t))
	got := text[i+len(begin) : j]
	if got == want {
		return
	}
	// TG_UPDATE_HARNESS_EVIDENCE=1 rewrites the block instead of failing. It
	// is the only supported way to change the text between the two markers.
	if os.Getenv("TG_UPDATE_HARNESS_EVIDENCE") == "1" {
		path := filepath.Join("..", "..", "docs", "support-matrix.md")
		if err := os.WriteFile(path, []byte(text[:i+len(begin)]+want+text[j:]), 0o644); err != nil {
			t.Fatalf("write docs/support-matrix.md: %v", err)
		}
		t.Logf("rewrote the harness-evidence block in docs/support-matrix.md")
		return
	}
	t.Errorf("the block between the harness-evidence markers differs from the manifest.\nRun: TG_UPDATE_HARNESS_EVIDENCE=1 go test ./cmd/tg/ -run TestSupportMatrixEvidenceBlockMatchesManifest -count=1")
}

func TestVerifiedMatrixRowsHaveManifestEvidence(t *testing.T) {
	m := loadHarnessManifest(t)
	// The loop below takes one passing start configuration as enough, and
	// the matrix says the same.
	requireSentences(t, readRepoFile(t, "docs", "support-matrix.md"),
		"passed for that harness in at least one of the start configurations in the table.")
	for name, status := range loadSupportMatrix(t) {
		if status != "verified" {
			continue
		}
		proven := false
		for _, h := range m.Harnesses {
			if manifestMatrixName[h.ID] != name {
				continue
			}
			passed := map[string]bool{}
			for _, s := range h.Stages {
				passed[s.ID] = s.Result == "PASS" && s.Expect != "measure"
			}
			if !passed["shell_deny"] || !passed["shell_allow_control"] {
				continue
			}
			proven = true
			if vs := matrixVersions(loadMatrixLine(t, name)); !slices.Contains(vs, h.VersionNumber) {
				t.Errorf("matrix row %q names versions %v, the manifest measured %s: capture the corpus again at the measured version, then add that version to the row", name, vs, h.VersionNumber)
			}
		}
		if !proven {
			t.Errorf("matrix row %q is marked verified, but the manifest holds no configuration of it in which the stages shell_deny and shell_allow_control both passed", name)
		}
	}
}

// TestSupportMatrixKeepsShellWriteCaveat pins the one hand-written caveat that
// is a fact about a shipped policy and not about a harness.
func TestSupportMatrixKeepsShellWriteCaveat(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "support-matrix.md"))
	if err != nil {
		t.Fatalf("read docs/support-matrix.md: %v", err)
	}
	if want := "scoped to the `filesystem_writes` tool group"; !strings.Contains(string(raw), want) {
		t.Errorf("docs/support-matrix.md no longer says the context-files policy is %s", want)
	}
}

// TestUnreleasedDocsCiteOnlyExistingTests fails when the Unreleased section of
// CHANGELOG.md, or docs/support-matrix.md, names a test function in backticks
// that no _test.go file of this package defines. A removed or renamed test
// must not stay cited as evidence.
func TestUnreleasedDocsCiteOnlyExistingTests(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("list test files: %v (found %d)", err, len(files))
	}
	defined := map[string]bool{}
	fn := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range fn.FindAllStringSubmatch(string(src), -1) {
			defined[m[1]] = true
		}
	}
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(raw)
	}
	changelog := read("CHANGELOG.md")
	const heading = "\n## [Unreleased]"
	i := strings.Index(changelog, heading)
	if i < 0 {
		t.Fatalf("CHANGELOG.md has no line that starts with %q", strings.TrimSpace(heading))
	}
	unreleased := changelog[i+len(heading):]
	if j := strings.Index(unreleased, "\n## ["); j >= 0 {
		unreleased = unreleased[:j]
	}
	cite := regexp.MustCompile("`(Test[A-Z]\\w*)`")
	for _, doc := range []struct{ name, text string }{
		{"CHANGELOG.md, section Unreleased", unreleased},
		{"docs/support-matrix.md", read(filepath.Join("docs", "support-matrix.md"))},
	} {
		for _, m := range cite.FindAllStringSubmatch(doc.text, -1) {
			if !defined[m[1]] {
				t.Errorf("%s cites %s, and no test file in cmd/tg defines that function", doc.name, m[1])
			}
		}
	}
}
