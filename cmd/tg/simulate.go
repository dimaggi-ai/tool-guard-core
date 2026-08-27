package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

// cmdSimulate is the batch dry-run: evaluate a whole policy set against a
// JSONL stream of envelopes and report both raw decisions and applied actions,
// plus a per-rule fire count. It lets a policy author answer "what would this
// policy set do to yesterday's traffic?" BEFORE deploying — the same
// question the internal simulator answers, minus any product coupling.
//
// It runs the exact same engine.Evaluate the proxy and `tg evaluate` use,
// so a simulate verdict and a live verdict cannot diverge.
//
// Exit codes:
//
//	0  simulation ran (default)
//	3  simulation ran AND at least one applied action was denied, with -fail-on-deny set
//	   (lets CI gate a policy change that would start denying real traffic)
//	1  internal/input error (including an empty or malformed corpus under -fail-on-deny)
//	2  usage error
func cmdSimulate(args []string) int {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	policyDir := fs.String("policy-dir", "", "directory of *.yaml/*.yml policies to load (mutually exclusive with -policy)")
	policyFile := fs.String("policy", "", "single policy YAML (mutually exclusive with -policy-dir)")
	callsPath := fs.String("calls", "", "JSONL file of ActionEnvelopes, one per line (\"-\" reads stdin)")
	modeStr := fs.String("mode", "enforcement", "shadow | enforcement")
	asJSON := fs.Bool("json", false, "emit the summary as JSON instead of a table")
	examples := fs.Int("examples", 3, "show up to N example envelope_ids per non-allow decision (table mode)")
	failOnDeny := fs.Bool("fail-on-deny", false, "fail on an empty or malformed corpus, or exit 3 if any applied action is denied (shadow-only denies do not fail; useful in CI)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*policyDir == "") == (*policyFile == "") {
		fmt.Fprintln(os.Stderr, "simulate: exactly one of -policy-dir or -policy is required")
		return 2
	}
	if *callsPath == "" {
		fmt.Fprintln(os.Stderr, "simulate: -calls is required")
		return 2
	}

	mode := domain.PolicyModeEnforcement
	switch *modeStr {
	case "shadow":
		mode = domain.PolicyModeShadow
	case "enforcement", "":
	default:
		fmt.Fprintf(os.Stderr, "simulate: unknown -mode %q (must be shadow|enforcement)\n", *modeStr)
		return 2
	}

	policies, err := loadPolicySet(*policyDir, *policyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "simulate:", err)
		return 1
	}
	if len(policies) == 0 {
		fmt.Fprintln(os.Stderr, "simulate: no policies loaded")
		return 1
	}

	in := os.Stdin
	if *callsPath != "-" {
		f, err := os.Open(*callsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "simulate:", err)
			return 1
		}
		defer f.Close()
		in = f
	}

	ev := engine.NewEvaluator()
	sum := simSummary{
		decisions: map[domain.Decision]int{},
		actions:   map[domain.ActionTaken]int{},
		ruleFires: map[simRuleKey]int{},
		byRuleEff: map[simRuleKey]domain.Effect{},
		examples:  map[domain.Decision][]string{},
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate large envelopes
	line := 0
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		line++
		if raw == "" {
			continue
		}
		var env *domain.ActionEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			sum.malformed++
			if sum.firstErr == "" {
				sum.firstErr = fmt.Sprintf("line %d: %v", line, err)
			}
			continue
		}
		if env == nil || strings.TrimSpace(env.ToolName) == "" {
			sum.malformed++
			if sum.firstErr == "" {
				sum.firstErr = fmt.Sprintf("line %d: action envelope must be a non-null JSON object with a non-empty tool_name", line)
			}
			continue
		}
		if env.Timestamp.IsZero() {
			env.Timestamp = time.Now().UTC()
		}
		res := ev.Evaluate(env, policies, mode)
		sum.total++
		sum.decisions[res.Decision]++
		sum.actions[res.ActionTaken]++
		if res.Decision != domain.DecisionAllowed && len(sum.examples[res.Decision]) < *examples {
			id := env.EnvelopeID
			if id == "" {
				id = fmt.Sprintf("line:%d", line)
			}
			sum.examples[res.Decision] = append(sum.examples[res.Decision], id)
		}
		for _, rr := range res.RuleResults {
			if rr.Matched {
				key := simRuleKey{PolicyID: rr.PolicyID, PolicyVersion: rr.PolicyVersion, RuleID: rr.RuleID}
				sum.ruleFires[key]++
				sum.byRuleEff[key] = rr.Effect
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "simulate: read calls:", err)
		return 1
	}

	if *asJSON {
		sum.printJSON(len(policies))
	} else {
		sum.printTable(len(policies), *examples)
	}

	if *failOnDeny {
		if sum.malformed > 0 {
			return 1
		}
		if sum.total == 0 {
			return 1
		}
		if sum.actions[domain.ActionDenied] > 0 {
			return 3
		}
	}
	return 0
}

// loadPolicySet loads one policy file or every *.yaml/*.yml in a dir,
// validating each through the same gate the proxy uses at load.
func loadPolicySet(dir, file string) ([]domain.Policy, error) {
	var paths []string
	if file != "" {
		paths = []string{file}
	} else {
		for _, ext := range []string{"*.yaml", "*.yml"} {
			matches, err := filepath.Glob(filepath.Join(dir, ext))
			if err != nil {
				return nil, err
			}
			paths = append(paths, matches...)
		}
		sort.Strings(paths)
	}
	var out []domain.Policy
	for _, p := range paths {
		pol, err := policyload.Load(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if err := engine.ValidatePolicy(&pol); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, pol)
	}
	if err := engine.ValidatePolicySet(out); err != nil {
		return nil, fmt.Errorf("validate policy set: %w", err)
	}
	return out, nil
}

type simRuleKey struct {
	PolicyID      string
	PolicyVersion int
	RuleID        string
}

func (k simRuleKey) label() string {
	return fmt.Sprintf("%s@v%d/%s", k.PolicyID, k.PolicyVersion, k.RuleID)
}

type simSummary struct {
	total     int
	malformed int
	firstErr  string
	decisions map[domain.Decision]int
	actions   map[domain.ActionTaken]int
	ruleFires map[simRuleKey]int
	byRuleEff map[simRuleKey]domain.Effect
	examples  map[domain.Decision][]string
}

var simDecisionOrder = []domain.Decision{
	domain.DecisionAllowed, domain.DecisionFlagged,
	domain.DecisionEscalated, domain.DecisionDenied,
}

var simActionOrder = []domain.ActionTaken{
	domain.ActionAllowed, domain.ActionAllowedShadow, domain.ActionFlagged,
	domain.ActionEscalated, domain.ActionDenied,
}

func (s *simSummary) printTable(policyCount, exampleN int) {
	fmt.Printf("Tool Guard simulate — %d policies, %d calls", policyCount, s.total)
	if s.malformed > 0 {
		fmt.Printf(", %d malformed (skipped)", s.malformed)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 48))
	fmt.Println("  rule decisions (what policy logic concluded):")
	for _, d := range simDecisionOrder {
		n := s.decisions[d]
		pct := 0.0
		if s.total > 0 {
			pct = 100 * float64(n) / float64(s.total)
		}
		fmt.Printf("  %-10s %6d  %5.1f%%\n", d, n, pct)
		if exampleN > 0 && d != domain.DecisionAllowed {
			if ex := s.examples[d]; len(ex) > 0 {
				fmt.Printf("             e.g. %s\n", strings.Join(ex, ", "))
			}
		}
	}
	fmt.Println(strings.Repeat("─", 48))
	fmt.Println("  applied actions (what would execute):")
	for _, action := range simActionOrder {
		n := s.actions[action]
		pct := 0.0
		if s.total > 0 {
			pct = 100 * float64(n) / float64(s.total)
		}
		fmt.Printf("  %-14s %6d  %5.1f%%\n", action, n, pct)
	}
	if len(s.ruleFires) > 0 {
		fmt.Println(strings.Repeat("─", 48))
		fmt.Println("  rule fires (by policy_id@version/rule_id):")
		type rf struct {
			key simRuleKey
			n   int
			eff domain.Effect
		}
		rows := make([]rf, 0, len(s.ruleFires))
		for key, n := range s.ruleFires {
			rows = append(rows, rf{key, n, s.byRuleEff[key]})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].n != rows[j].n {
				return rows[i].n > rows[j].n
			}
			return rows[i].key.label() < rows[j].key.label()
		})
		for _, r := range rows {
			fmt.Printf("    %-40s %6d  [%s]\n", r.key.label(), r.n, r.eff)
		}
	}
	if s.firstErr != "" {
		fmt.Println(strings.Repeat("─", 48))
		fmt.Printf("  first parse error: %s\n", s.firstErr)
	}
}

func (s *simSummary) printJSON(policyCount int) {
	decisions := map[string]int{}
	for d, n := range s.decisions {
		decisions[string(d)] = n
	}
	actions := map[string]int{}
	for action, n := range s.actions {
		actions[string(action)] = n
	}
	type ruleFire struct {
		PolicyID      string `json:"policy_id"`
		PolicyVersion int    `json:"policy_version"`
		RuleID        string `json:"rule_id"`
		Fires         int    `json:"fires"`
		Effect        string `json:"effect"`
	}
	rules := make([]ruleFire, 0, len(s.ruleFires))
	for key, n := range s.ruleFires {
		rules = append(rules, ruleFire{
			PolicyID:      key.PolicyID,
			PolicyVersion: key.PolicyVersion,
			RuleID:        key.RuleID,
			Fires:         n,
			Effect:        string(s.byRuleEff[key]),
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Fires != rules[j].Fires {
			return rules[i].Fires > rules[j].Fires
		}
		if rules[i].PolicyID != rules[j].PolicyID {
			return rules[i].PolicyID < rules[j].PolicyID
		}
		if rules[i].PolicyVersion != rules[j].PolicyVersion {
			return rules[i].PolicyVersion < rules[j].PolicyVersion
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	out := map[string]any{
		"policies":   policyCount,
		"total":      s.total,
		"malformed":  s.malformed,
		"decisions":  decisions,
		"actions":    actions,
		"rule_fires": rules,
	}
	if s.firstErr != "" {
		out["first_parse_error"] = s.firstErr
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
