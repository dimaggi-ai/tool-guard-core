// tg is the Tool Guard Core CLI. Key data-plane verbs:
//
//	tg evaluate -policy POLICY.yaml -call CALL.json     # run one tool call against one policy
//	tg verify   -file DECISIONS.jsonl                   # replay the audit chain offline
//	tg export   -file DECISIONS.jsonl -format jsonl     # stream records for external log tooling
//	tg lint     -policy POLICY.yaml                     # warn on scope-too-narrow + other footguns
//	tg benchmark                                        # report deterministic eval p99 on this host
//
// The CLI deliberately speaks plain JSONL and YAML so it composes with
// shell pipelines (`tg evaluate ... | jq`). It has no DB dependency — the
// audit it produces is a JSONL stream you redirect to a file.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
	// Register the default SQL dialect classifiers (postgres/mysql/sqlite via
	// lite, plus mssql) by side-effect so `tg evaluate`/`tg lint` classify
	// sql_classify policies for real instead of fail-closing on an
	// unregistered dialect. Must match cmd/tg-proxy/main.go.
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mssql"
)

const usage = `tg — Tool Guard Core CLI

Usage:
  tg evaluate  -policy POLICY.yaml -call CALL.json [-mode shadow|enforcement]
  tg simulate  (-policy-dir DIR | -policy POLICY.yaml) -calls CALLS.jsonl
  tg coverage  (-policy-dir DIR | -policy POLICY.yaml) -calls CALLS.jsonl
  tg hook      (-policy-dir DIR | -policy POLICY.yaml) [-protect-self] [-fail-closed-tools ...]
  tg protect   claude [-apply] [-config PATH] [-policy PATH] [-tg PATH]
  tg status    [claude] [-config PATH]
  tg unprotect claude [-apply] [-config PATH]
  tg verify    -file DECISIONS.jsonl
  tg export    -file DECISIONS.jsonl [-format jsonl] [-since RFC3339] [-until RFC3339] [-policy ID] [-action ACTION]
  tg lint      -policy POLICY.yaml
  tg benchmark [-trials N]
  tg version

Run "tg <verb> -h" for verb-specific flags.
`

// Version, Commit, and BuildDate are injected by the release pipeline
// via -ldflags (see .goreleaser.yaml). They stay empty for plain
// `go build`, in which case printVersion falls back to the module
// version from ReadBuildInfo ("(devel)" for local builds).
var (
	Version   string
	Commit    string
	BuildDate string
)

func resolvedEngineVersion() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "(devel)"
}

// printVersion writes the release version (ldflags-injected) or the
// module version embedded in the binary, plus the Go toolchain version.
func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if Version != "" {
		fmt.Printf("tg %s (commit %s, built %s)\n", Version, Commit, BuildDate)
		if ok {
			fmt.Printf("go %s\n", info.GoVersion)
		}
		return
	}
	if !ok {
		fmt.Println("tg: build info unavailable")
		return
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		v = "(devel)"
	}
	fmt.Printf("tg %s\n", v)
	fmt.Printf("go %s\n", info.GoVersion)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	verb := os.Args[1]
	args := os.Args[2:]
	switch verb {
	case "evaluate":
		os.Exit(cmdEvaluate(args))
	case "simulate":
		os.Exit(cmdSimulate(args))
	case "coverage":
		os.Exit(cmdCoverage(args))
	case "hook":
		os.Exit(cmdHook(args))
	case "protect":
		os.Exit(cmdProtect(args))
	case "status":
		os.Exit(cmdProtectStatus(args))
	case "unprotect":
		os.Exit(cmdUnprotect(args))
	case "verify":
		os.Exit(cmdVerify(args))
	case "export":
		os.Exit(cmdExport(args))
	case "lint":
		os.Exit(cmdLint(args))
	case "benchmark":
		os.Exit(cmdBenchmark(args))
	case "version", "-version", "--version":
		printVersion()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "tg: unknown verb %q\n%s", verb, usage)
		os.Exit(2)
	}
}

// ── tg evaluate ────────────────────────────────────────────────────────────
//
// Reads ONE policy (YAML) and ONE tool call (JSON), runs them through the
// engine, and prints the decision as a single JSONL line. Exit 0 on
// allow (and allowed_shadow), 3 on deny, 4 on escalate.
//
// Note on -mode: the effective mode is the STRICTEST of the -mode flag
// and the policy YAML's own `mode:` field. A policy marked
// `mode: enforcement` cannot be downgraded to shadow from the CLI —
// policy authors govern the floor; the CLI can only raise the bar.

func cmdEvaluate(args []string) int {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	callPath := fs.String("call", "", "Path to tool-call JSON")
	modeStr := fs.String("mode", "enforcement", "shadow | enforcement")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *callPath == "" {
		fmt.Fprintln(os.Stderr, "evaluate: -policy and -call are required")
		fs.Usage()
		return 2
	}

	policy, err := policyload.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evaluate:", err)
		return 1
	}
	// Same structural gate the proxy applies at load: unknown effects,
	// bad regexes/types/depth, classifiers under not:, etc. must refuse
	// to evaluate rather than silently fail open.
	if err := engine.ValidatePolicy(&policy); err != nil {
		fmt.Fprintln(os.Stderr, "evaluate:", err)
		return 1
	}
	env, err := loadEnvelopeJSON(*callPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evaluate:", err)
		return 1
	}
	mode := domain.PolicyModeEnforcement
	switch *modeStr {
	case "shadow":
		mode = domain.PolicyModeShadow
	case "enforcement", "":
	default:
		fmt.Fprintf(os.Stderr, "evaluate: unknown -mode %q (must be shadow|enforcement)\n", *modeStr)
		return 2
	}

	result := engine.NewEvaluator().Evaluate(env, []domain.Policy{policy}, mode)
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "evaluate: encode:", err)
		return 1
	}
	switch result.ActionTaken {
	case domain.ActionDenied:
		return 3
	case domain.ActionEscalated:
		return 4
	}
	return 0
}

// ── tg verify ──────────────────────────────────────────────────────────────
//
// Replays a JSONL stream of decision traces and reports whether the audit
// chain is intact. Exit 0 only when every record links cleanly.

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to decisions.jsonl (rotated siblings <file>.1, <file>.2, ... are auto-included in reverse order so the oldest comes first)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "verify: -file is required")
		return 2
	}

	fileSet, err := openVerifiedAuditFileSet(*filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	defer fileSet.close()
	report := fileSet.report
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "verify: encode:", err)
		return 1
	}
	if !report.Intact {
		return 5
	}
	return 0
}

// ── tg lint ────────────────────────────────────────────────────────────────
//
// Static checks on a policy YAML for the footguns the battle test
// surfaced. Today this applies eight heuristics; the list grows as we
// surface more bypass classes.

type LintFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // "warn" | "error"
	Message  string `json:"message"`
	Suggest  string `json:"suggest,omitempty"`
}

func cmdLint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "lint: -policy is required")
		return 2
	}
	policy, err := policyload.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lint:", err)
		return 1
	}

	// Structural validation (engine load-time checks) — empty
	// conditions, bad regex, depth limits. Surface as error-severity
	// findings so policy authors catch them before the proxy
	// refuses-to-load at runtime.
	findings := lintPolicy(policy)
	if err := engine.ValidatePolicy(&policy); err != nil {
		findings = append(findings, LintFinding{
			Rule:     "structural-validation",
			Severity: "error",
			Message:  err.Error(),
			Suggest:  "fix the condition shape; this policy will be rejected by tg-proxy at load time",
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		fmt.Fprintln(os.Stderr, "lint: encode:", err)
		return 1
	}
	for _, f := range findings {
		if f.Severity == "error" {
			return 6
		}
	}
	return 0
}

// lintPolicy applies every heuristic. Kept as plain Go (no reflection, no
// rule DSL) so a CTO can read the rule set in 30 seconds.
func lintPolicy(p domain.Policy) []LintFinding {
	out := []LintFinding{}

	// Heuristic 0: empty scope (policy-scope-leak). A policy with no
	// tool_names AND no tool_groups runs on every tool call across the
	// org, which means every call carries the policy's eval cost and is
	// a candidate for false-positive denies. Almost never what the
	// author intended — so a designed floor must declare itself with
	// scope.intentionally_global: true, which suppresses this finding.
	if len(p.Scope.ToolNames) == 0 && len(p.Scope.ToolGroups) == 0 && !p.Scope.IntentionallyGlobal {
		out = append(out, LintFinding{
			Rule:     "policy-scope-leak",
			Severity: "warn",
			Message:  "policy has empty scope (no tool_names and no tool_groups) — it will evaluate on every tool call, including unrelated ones, raising the false-positive deny rate and per-call latency",
			Suggest:  "add scope.tool_names or scope.tool_groups to constrain which tools this policy guards, or declare scope.intentionally_global: true if evaluating on every call is the design (e.g. a floor policy)",
		})
	}

	// Heuristic 0b: intentionally_global alongside a tool selector is a
	// contradiction — the selector wins (matching gates on it), so the
	// declaration misdocuments the policy's actual reach.
	if p.Scope.IntentionallyGlobal && (len(p.Scope.ToolNames) > 0 || len(p.Scope.ToolGroups) > 0) {
		out = append(out, LintFinding{
			Rule:     "global-scope-contradiction",
			Severity: "warn",
			Message:  "scope.intentionally_global is true but tool_names/tool_groups are also set — the selectors gate matching, so the policy is NOT global and the declaration misdocuments it",
			Suggest:  "remove scope.intentionally_global, or remove the tool selectors if the policy is meant to evaluate on every call",
		})
	}

	// Heuristic 1: narrow scope. The battle-test "tool-substitution"
	// bypass class (5/5 in the v1 results) is caused by scoping a rule
	// to ONE tool name when the underlying intent is to govern a whole
	// tool group. Warn loudly.
	if len(p.Scope.ToolNames) > 0 && len(p.Scope.ToolGroups) == 0 {
		out = append(out, LintFinding{
			Rule:     "scope-no-tool-group",
			Severity: "warn",
			Message:  "policy scopes tool_names but no tool_groups; an attacker can pivot to a sibling tool in the same group and slip the rule",
			Suggest:  "add the relevant tool_groups: [...] alongside (or instead of) tool_names",
		})
	}

	// Heuristic 2: structured-amount threshold without a free-text
	// consistency check. If a rule gates on the structured `amount`
	// field, an attacker can write the real intent ("$1000") in the
	// reason field while passing amount=100 → the deterministic check
	// is silent on the discrepancy. Surfaces the "amount-fragmentation"
	// bypass class — see docs/battle-test-results.md.
	//
	// Mitigations that suppress the warning:
	//   1. A regex / contains rule on a free-text parameter field
	//      (parameters.* other than `amount`). The strict variant ships
	//      `\$[0-9,]{3,}` on parameters.reason and lints cleanly.
	//   2. A sql_classify / shell_classify / path_classify rule —
	//      those inspect string fields semantically.
	if len(p.Rules) > 0 {
		hasAmountThreshold := false
		hasFreeTextCheck := false
		for _, r := range p.Rules {
			if r.Conditions.Field == "amount" {
				hasAmountThreshold = true
			}
			if conditionChecksFreeText(r.Conditions) {
				hasFreeTextCheck = true
			}
		}
		if hasAmountThreshold && !hasFreeTextCheck {
			out = append(out, LintFinding{
				Rule:     "amount-without-semantic-check",
				Severity: "warn",
				Message:  "rule gates on the structured amount field only; an agent can pass amount=100 with '$1000' written into reason and bypass the threshold",
				Suggest:  "add an explicit regex check on free-text fields, or keep enforceable values in structured fields only -- the deterministic engine never reads free text",
			})
		}
	}

	// Heuristic 3: rule with no citation. Cuts the "where did this rule
	// come from" question every auditor asks.
	for _, r := range p.Rules {
		if r.Citation.DocumentID == "" && r.Citation.Excerpt == "" {
			out = append(out, LintFinding{
				Rule:     "rule-missing-citation",
				Severity: "warn",
				Message:  fmt.Sprintf("rule %q has no citation; auditors cannot trace it back to a source document", r.RuleID),
				Suggest:  "add citation: { document_id, excerpt } pointing to the SOP/regulation that motivates the rule",
			})
		}
	}

	// Heuristic 4: rule_id collision within the policy. Duplicate rule
	// IDs make audit traces ambiguous (which rule matched? which
	// suggested response applies?) and they break by-ID lookups in
	// FindSuggestedResponse (only the last wins).
	seen := make(map[string]int, len(p.Rules))
	for _, r := range p.Rules {
		if r.RuleID == "" {
			continue
		}
		seen[r.RuleID]++
	}
	for id, n := range seen {
		if n > 1 {
			out = append(out, LintFinding{
				Rule:     "rule-id-collision",
				Severity: "error",
				Message:  fmt.Sprintf("rule_id %q appears %d times in this policy; audit lookups and suggested-response resolution become ambiguous", id, n),
				Suggest:  "rename one of the duplicates so every rule_id is unique within the policy",
			})
		}
	}

	// Heuristic 5: regex condition with invalid pattern. The engine
	// safely returns false on a bad regex at runtime, so the policy
	// silently never matches — exactly the failure mode authors miss.
	// Catch it at lint time instead.
	for _, r := range p.Rules {
		// Walk the condition tree; the engine's only regex operator is
		// "regex". A "matches" operator does not exist in the engine and
		// is caught separately by the unknown-operator heuristic below.
		bad := collectBadRegexes(r.Conditions)
		for _, pat := range bad {
			out = append(out, LintFinding{
				Rule:     "invalid-regex-syntax",
				Severity: "error",
				Message:  fmt.Sprintf("rule %q has a regex pattern that does not compile: %q", r.RuleID, pat),
				Suggest:  "fix the regex; the engine returns false on a bad pattern, so the rule will silently never match",
			})
		}
	}

	// Heuristic 6: unknown operator. The engine evaluates a fixed set of
	// operator strings; anything else falls through condition.evalLeaf's
	// default branch and silently returns false (same silent-no-match
	// failure mode as a bad regex).
	for _, r := range p.Rules {
		for _, op := range collectUnknownOperators(r.Conditions) {
			out = append(out, LintFinding{
				Rule:     "unknown-operator",
				Severity: "error",
				Message:  fmt.Sprintf("rule %q uses operator %q, which the engine does not implement; the leaf will always evaluate to false", r.RuleID, op),
				Suggest:  "use one of: eq, neq, gt, gte, lt, lte, in, contains, regex, gt_field, lt_field (see pkg/engine/condition.go)",
			})
		}
	}

	// Heuristic 7: writable scope without self-protection. A policy that
	// admits write-capable tools (write/edit/notebookedit or a shell tool)
	// can, by construction, edit files — including its own YAML and the
	// audit log. If no rule uses a path_classify deny/escalate leaf, the
	// policy has no in-band tripwire against writes to sensitive paths. The
	// robust fix is operator-side (tg-proxy / tg hook -protect-paths /
	// -protect-self), which a policy cannot disable; a path_classify rule is
	// the in-policy mitigation. WARNING only — many shell policies gate by
	// regex intentionally, so this is advisory, not an error.
	if admits := writableToolsInScope(p.Scope); len(admits) > 0 && !policyHasPathProtection(p) {
		out = append(out, LintFinding{
			Rule:     "writable-scope-no-self-protection",
			Severity: "warn",
			Message:  fmt.Sprintf("policy grants write-capable tools (%s) but no rule uses path_classify to protect sensitive paths; a policy that can edit files should protect its own config — add a path_classify deny rule or run tg-proxy/tg hook with -protect-paths", strings.Join(admits, ", ")),
			Suggest:  "add a path_classify deny/escalate rule covering the policy dir + audit log, or run the proxy/hook with -protect-paths / -protect-self (unconditional, cannot be edited away by the agent)",
		})
	}

	return out
}

// writableToolCatalog is the closed set of tool names the
// writable-scope-no-self-protection heuristic treats as write-capable
// (file mutators + shell executors). Matched case-insensitively so the
// coding-agent forms (Bash, Write, Edit, NotebookEdit) are caught.
var writableToolCatalog = map[string]struct{}{
	"write": {}, "edit": {}, "notebookedit": {},
	"bash": {}, "shell": {}, "run_command": {},
}

// writableToolsInScope returns the write-capable tool names a policy's scope
// admits. An empty scope (no tool_names AND no tool_groups) matches every
// tool, so it admits the whole catalog. Otherwise only the explicitly-listed
// tool_names are considered (a tool_groups-only scope names no concrete
// write tool, so it does not trip this heuristic).
func writableToolsInScope(scope domain.PolicyScope) []string {
	if len(scope.ToolNames) == 0 && len(scope.ToolGroups) == 0 {
		return []string{"empty scope — all tools"}
	}
	var out []string
	for _, n := range scope.ToolNames {
		if _, ok := writableToolCatalog[strings.ToLower(strings.TrimSpace(n))]; ok {
			out = append(out, n)
		}
	}
	return out
}

// policyHasPathProtection reports whether any deny/escalate rule uses a
// path_classify leaf anywhere in its condition tree — the in-policy
// tripwire the writable-scope heuristic looks for.
func policyHasPathProtection(p domain.Policy) bool {
	for _, r := range p.Rules {
		if r.Effect != domain.EffectDeny && r.Effect != domain.EffectEscalate {
			continue
		}
		if conditionHasPathClassify(r.Conditions) {
			return true
		}
	}
	return false
}

// conditionHasPathClassify walks a condition tree for a PathClassify leaf.
func conditionHasPathClassify(c domain.Condition) bool {
	if c.PathClassify != nil {
		return true
	}
	for _, ch := range c.And {
		if conditionHasPathClassify(ch) {
			return true
		}
	}
	for _, ch := range c.Or {
		if conditionHasPathClassify(ch) {
			return true
		}
	}
	if c.Not != nil {
		return conditionHasPathClassify(*c.Not)
	}
	return false
}

// knownOperators is the closed set the engine's condition.evalLeaf knows
// how to evaluate. Anything outside this set silently never matches at
// runtime; surface it at lint time as an error.
//
// Kept in sync with the Op* constants in pkg/domain/policy.go and the
// switch in pkg/engine/condition.go:evalLeaf. A previous version was
// missing gt_field / lt_field, which would have lint-failed any valid
// policy doing field-to-field comparisons. Two regressions pin this
// now: TestLint_AcceptsAllKnownOperators (table) and
// TestLint_AllDomainOperatorsRegistered (AST coupling).
var knownOperators = map[string]struct{}{
	"eq": {}, "neq": {},
	"gt": {}, "gte": {}, "lt": {}, "lte": {},
	"in": {}, "contains": {}, "regex": {},
	"gt_field": {}, "lt_field": {},
	// v0.2.0 negative / presence operators
	"not_in": {}, "not_contains": {},
	"starts_with": {}, "ends_with": {}, "exists": {},
}

// collectUnknownOperators walks a condition tree and returns operator
// strings that are non-empty but not in knownOperators. Branch nodes
// (And/Or/Not without an operator) are skipped.
// conditionChecksFreeText reports whether the condition tree contains any
// leaf that semantically inspects a string-shaped field — a regex or
// contains operator on a parameters.* field other than `amount`, or any
// sql_classify / shell_classify / path_classify leaf. Used by the
// amount-without-semantic-check heuristic so the warning is suppressed
// once the policy author has added the recommended tripwire.
func conditionChecksFreeText(c domain.Condition) bool {
	for _, child := range c.And {
		if conditionChecksFreeText(child) {
			return true
		}
	}
	for _, child := range c.Or {
		if conditionChecksFreeText(child) {
			return true
		}
	}
	if c.Not != nil && conditionChecksFreeText(*c.Not) {
		return true
	}
	if c.SQLClassify != nil || c.ShellClassify != nil || c.PathClassify != nil {
		return true
	}
	op := string(c.Operator)
	if op == "regex" || op == "contains" {
		// regex / contains on the structured `amount` field doesn't count
		// — that's still the amount-fragmentation bypass surface. Any
		// other field (especially parameters.reason, parameters.sql,
		// parameters.path, etc.) does.
		if c.Field == "" || c.Field == "amount" {
			return false
		}
		// For regex specifically the pattern must actually compile.
		// A broken regex doesn't mitigate anything — invalid-regex-syntax
		// would also fire on it, and we want both warnings to surface.
		if op == "regex" {
			pat, ok := c.Value.(string)
			if !ok {
				return false
			}
			if _, err := regexp.Compile(pat); err != nil {
				return false
			}
		}
		return true
	}
	return false
}

func collectUnknownOperators(c domain.Condition) []string {
	var bad []string
	for _, child := range c.And {
		bad = append(bad, collectUnknownOperators(child)...)
	}
	for _, child := range c.Or {
		bad = append(bad, collectUnknownOperators(child)...)
	}
	if c.Not != nil {
		bad = append(bad, collectUnknownOperators(*c.Not)...)
	}
	op := string(c.Operator)
	if op == "" {
		return bad
	}
	if _, ok := knownOperators[op]; !ok {
		bad = append(bad, op)
	}
	return bad
}

// collectBadRegexes walks a condition tree and returns the literal
// patterns of any leaves whose operator is "regex" but whose value does
// not compile. The engine implements only "regex" as a regex operator;
// the "unknown-operator" heuristic catches typos like "matches".
// Empty list when the tree contains no regex conditions or all patterns
// compile.
func collectBadRegexes(c domain.Condition) []string {
	var bad []string
	if len(c.And) > 0 {
		for _, child := range c.And {
			bad = append(bad, collectBadRegexes(child)...)
		}
	}
	if len(c.Or) > 0 {
		for _, child := range c.Or {
			bad = append(bad, collectBadRegexes(child)...)
		}
	}
	if c.Not != nil {
		bad = append(bad, collectBadRegexes(*c.Not)...)
	}
	if string(c.Operator) == "regex" {
		if pat, ok := c.Value.(string); ok {
			if _, err := regexp.Compile(pat); err != nil {
				bad = append(bad, pat)
			}
		}
	}
	return bad
}

// ── tg benchmark ───────────────────────────────────────────────────────────
//
// Runs N synthetic evaluations and reports observed p50/p95/p99. Useful
// for verifying the README performance numbers on your own hardware.

func cmdBenchmark(args []string) int {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	trials := fs.Int("trials", 10000, "Number of synthetic evaluations")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	policy := domain.Policy{
		PolicyID: "bench-policy",
		Name:     "bench",
		Version:  1,
		Status:   domain.PolicyStatusApproved,
		Mode:     domain.PolicyModeEnforcement,
		Scope:    domain.PolicyScope{ToolNames: []string{"issue_refund"}},
		Rules: []domain.Rule{
			{
				RuleID:     "amount-cap",
				Name:       "Amount cap",
				Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
				Effect:     domain.EffectDeny,
				Citation:   domain.Citation{DocumentID: "bench-doc", Excerpt: "$500 cap"},
			},
		},
	}
	params, _ := json.Marshal(map[string]interface{}{"amount": 200})
	env := &domain.ActionEnvelope{
		EnvelopeID: "bench-env",
		Timestamp:  time.Now(),
		AgentID:    "bench-agent",
		SessionID:  "bench-sess",
		OrgID:      "bench-org",
		ToolName:   "issue_refund",
		ToolGroup:  "monetary_outflow",
		Parameters: params,
	}

	eval := engine.NewEvaluator()
	samples := make([]time.Duration, 0, *trials)
	ctx := context.Background()
	_ = ctx
	for i := 0; i < *trials; i++ {
		t0 := time.Now()
		_ = eval.Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
		samples = append(samples, time.Since(t0))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"trials": *trials,
		"p50_us": percentileUS(samples, 0.50),
		"p95_us": percentileUS(samples, 0.95),
		"p99_us": percentileUS(samples, 0.99),
		"max_us": maxUS(samples),
	})
	return 0
}

func percentileUS(s []time.Duration, p float64) int64 {
	if len(s) == 0 {
		return 0
	}
	// quick + dirty: copy, sort, index. Good enough for this CLI.
	tmp := make([]time.Duration, len(s))
	copy(tmp, s)
	insertionSort(tmp)
	idx := int(float64(len(tmp)-1) * p)
	return tmp[idx].Microseconds()
}

func maxUS(s []time.Duration) int64 {
	var m time.Duration
	for _, d := range s {
		if d > m {
			m = d
		}
	}
	return m.Microseconds()
}

func insertionSort(a []time.Duration) {
	for i := 1; i < len(a); i++ {
		k := a[i]
		j := i - 1
		for j >= 0 && a[j] > k {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = k
	}
}

func loadEnvelopeJSON(path string) (*domain.ActionEnvelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read call: %w", err)
	}
	var env domain.ActionEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("parse call: %w", err)
	}
	if env.Timestamp.IsZero() {
		env.Timestamp = time.Now()
	}
	if env.EnvelopeID == "" {
		env.EnvelopeID = fmt.Sprintf("env-%d", time.Now().UnixNano())
	}
	return &env, nil
}
