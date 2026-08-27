package main

// TestConformance walks testdata/conformance/*.json and asserts the engine
// produces the exact documented decision for each shipped policy + a real
// envelope. This is the "public conformance corpus green on every release
// and platform" item from the 1.0 roadmap made real: it runs as an
// ordinary `go test` in the existing 3-OS CI matrix (ubuntu/macos/windows),
// so it's already checked on every platform that matrix covers — no
// separate infrastructure needed.
//
// See testdata/conformance/README.md for the case schema and how to add
// one.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

type conformanceCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	PolicyFile  string   `json:"policy_file,omitempty"`
	PolicyFiles []string `json:"policy_files,omitempty"`
	// PolicyCompatSince is the earliest frozen policy snapshot whose policy
	// content supports this case. Empty means every snapshot containing the
	// referenced policy. It does not affect current conformance evaluation.
	PolicyCompatSince string                 `json:"policy_compat_since,omitempty"`
	Mode              string                 `json:"mode"`
	Envelope          domain.ActionEnvelope  `json:"envelope"`
	Expect            conformanceExpectation `json:"expect"`
}

type conformanceExpectation struct {
	Decision       string   `json:"decision"`
	ActionTaken    string   `json:"action_taken"`
	MatchedRuleIDs []string `json:"matched_rule_ids,omitempty"`
}

func decodeConformanceCase(raw []byte) (conformanceCase, error) {
	var c conformanceCase
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("decode strict case schema: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return c, fmt.Errorf("decode strict case schema: trailing JSON value")
		}
		return c, fmt.Errorf("decode strict case schema: trailing data: %w", err)
	}
	if err := validateConformanceCase(c); err != nil {
		return c, err
	}
	return c, nil
}

func validateConformanceCase(c conformanceCase) error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("case name is required")
	}
	if strings.TrimSpace(c.Description) == "" {
		return fmt.Errorf("case %q: description is required", c.Name)
	}
	paths, err := c.policyPaths()
	if err != nil {
		return fmt.Errorf("case %q: %w", c.Name, err)
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("case %q: policy path cannot be blank", c.Name)
		}
		if filepath.IsAbs(path) {
			return fmt.Errorf("case %q: policy path %q must be relative to the case file", c.Name, path)
		}
		clean := filepath.Clean(path)
		if _, duplicate := seenPaths[clean]; duplicate {
			return fmt.Errorf("case %q: duplicate policy path %q", c.Name, path)
		}
		seenPaths[clean] = struct{}{}
	}
	if c.PolicyCompatSince != "" {
		if _, err := parseReleaseVersion(c.PolicyCompatSince); err != nil {
			return fmt.Errorf("case %q: invalid policy_compat_since: %w", c.Name, err)
		}
	}

	switch c.Mode {
	case string(domain.PolicyModeEnforcement), string(domain.PolicyModeShadow):
	default:
		return fmt.Errorf("case %q: mode must be enforcement or shadow, got %q", c.Name, c.Mode)
	}
	if strings.TrimSpace(c.Envelope.ToolName) == "" {
		return fmt.Errorf("case %q: envelope.tool_name is required", c.Name)
	}
	if raw := bytes.TrimSpace(c.Envelope.Parameters); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		var object map[string]interface{}
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fmt.Errorf("case %q: envelope.parameters must be a JSON object", c.Name)
		}
	}

	validDecisions := map[string]struct{}{
		string(domain.DecisionAllowed): {}, string(domain.DecisionDenied): {},
		string(domain.DecisionEscalated): {}, string(domain.DecisionFlagged): {},
	}
	if _, ok := validDecisions[c.Expect.Decision]; !ok {
		return fmt.Errorf("case %q: invalid expect.decision %q", c.Name, c.Expect.Decision)
	}
	validActions := map[string]struct{}{
		string(domain.ActionAllowed): {}, string(domain.ActionDenied): {},
		string(domain.ActionEscalated): {}, string(domain.ActionFlagged): {},
		string(domain.ActionAllowedShadow): {},
	}
	if _, ok := validActions[c.Expect.ActionTaken]; !ok {
		return fmt.Errorf("case %q: invalid expect.action_taken %q", c.Name, c.Expect.ActionTaken)
	}
	if c.Expect.Decision != string(domain.DecisionAllowed) && len(c.Expect.MatchedRuleIDs) == 0 {
		return fmt.Errorf("case %q: non-allow result requires expect.matched_rule_ids", c.Name)
	}
	for _, ruleID := range c.Expect.MatchedRuleIDs {
		if strings.TrimSpace(ruleID) == "" {
			return fmt.Errorf("case %q: expect.matched_rule_ids cannot contain a blank ID", c.Name)
		}
	}
	return nil
}

func (c conformanceCase) policyPaths() ([]string, error) {
	hasSingle := strings.TrimSpace(c.PolicyFile) != ""
	hasMany := len(c.PolicyFiles) > 0
	if hasSingle == hasMany {
		return nil, fmt.Errorf("set exactly one of policy_file or policy_files")
	}
	if hasSingle {
		return []string{c.PolicyFile}, nil
	}
	return slices.Clone(c.PolicyFiles), nil
}

func loadConformancePolicies(caseFile string, c conformanceCase) ([]domain.Policy, error) {
	paths, err := c.policyPaths()
	if err != nil {
		return nil, err
	}
	policies := make([]domain.Policy, 0, len(paths))
	for _, path := range paths {
		policy, err := policyload.Load(filepath.Join(filepath.Dir(caseFile), path))
		if err != nil {
			return nil, fmt.Errorf("load policy %q: %w", path, err)
		}
		if err := engine.ValidatePolicy(&policy); err != nil {
			return nil, fmt.Errorf("policy %q fails validation: %w", path, err)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func evaluateConformanceCase(c conformanceCase, policies []domain.Policy) *domain.EvaluationResult {
	env := c.Envelope
	if env.Timestamp.IsZero() {
		env.Timestamp = time.Now()
	}
	if env.EnvelopeID == "" {
		env.EnvelopeID = "conformance-" + c.Name
	}
	return engine.NewEvaluator().Evaluate(&env, policies, domain.PolicyMode(c.Mode))
}

func TestShadowConformanceFixtureDiffersOnlyByMode(t *testing.T) {
	base, err := policyload.Load(filepath.Join("..", "..", "policies", "refund_cap.yaml"))
	if err != nil {
		t.Fatalf("load shipped refund policy: %v", err)
	}
	shadow, err := policyload.Load(filepath.Join("..", "..", "testdata", "conformance", "fixtures", "refund_cap_shadow.yaml"))
	if err != nil {
		t.Fatalf("load shadow fixture: %v", err)
	}
	if base.Mode != domain.PolicyModeEnforcement || shadow.Mode != domain.PolicyModeShadow {
		t.Fatalf("fixture modes = base:%q shadow:%q, want enforcement/shadow", base.Mode, shadow.Mode)
	}
	shadow.Mode = base.Mode
	if !reflect.DeepEqual(shadow, base) {
		t.Fatal("shadow fixture drifted from policies/refund_cap.yaml in fields other than mode")
	}
}

func TestConformance(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "conformance", "*.json"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no conformance cases found — testdata/conformance/*.json is empty or the glob path is wrong")
	}

	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read case: %v", err)
			}
			c, err := decodeConformanceCase(raw)
			if err != nil {
				t.Fatalf("parse case: %v", err)
			}

			policies, err := loadConformancePolicies(file, c)
			if err != nil {
				t.Fatalf("load policies: %v", err)
			}

			result := evaluateConformanceCase(c, policies)

			if string(result.Decision) != c.Expect.Decision {
				t.Errorf("%s: decision = %q, want %q (reason: %s)",
					c.Description, result.Decision, c.Expect.Decision, result.DecisionReason)
			}
			if string(result.ActionTaken) != c.Expect.ActionTaken {
				t.Errorf("%s: action_taken = %q, want %q (reason: %s)",
					c.Description, result.ActionTaken, c.Expect.ActionTaken, result.DecisionReason)
			}
			if c.Expect.MatchedRuleIDs != nil {
				got := matchedRuleIDs(result.RuleResults)
				want := slices.Clone(c.Expect.MatchedRuleIDs)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("%s: matched_rule_ids = %q, want exact set %q",
						c.Description, got, want)
				}
			}
		})
	}
}

func TestDecodeConformanceCaseRejectsInvalidSchema(t *testing.T) {
	valid := `{
		"name":"schema_case",
		"description":"valid schema sentinel",
		"policy_file":"fixtures/example.yaml",
		"mode":"enforcement",
		"envelope":{"tool_name":"probe","parameters":{"value":1}},
		"expect":{"decision":"allowed","action_taken":"allowed"}
	}`
	tests := map[string]string{
		"unknown top-level field":       strings.Replace(valid, `"name":"schema_case"`, `"unknown":true,"name":"schema_case"`, 1),
		"unknown expectation field":     strings.Replace(valid, `"decision":"allowed"`, `"unknown":true,"decision":"allowed"`, 1),
		"trailing JSON value":           valid + ` {}`,
		"blank required field":          strings.Replace(valid, `"description":"valid schema sentinel"`, `"description":""`, 1),
		"both policy selectors":         strings.Replace(valid, `"policy_file":"fixtures/example.yaml"`, `"policy_file":"fixtures/example.yaml","policy_files":["fixtures/other.yaml"]`, 1),
		"non-object parameters":         strings.Replace(valid, `"parameters":{"value":1}`, `"parameters":[1]`, 1),
		"non-allow without matched IDs": strings.Replace(valid, `"decision":"allowed","action_taken":"allowed"`, `"decision":"denied","action_taken":"denied"`, 1),
		"duplicate policy path": strings.Replace(
			valid,
			`"policy_file":"fixtures/example.yaml"`,
			`"policy_files":["fixtures/example.yaml","fixtures/example.yaml"]`,
			1,
		),
		"invalid compatibility version": strings.Replace(valid, `"mode":"enforcement"`, `"policy_compat_since":"0.5","mode":"enforcement"`, 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConformanceCase([]byte(raw)); err == nil {
				t.Fatal("decodeConformanceCase() accepted invalid case schema")
			}
		})
	}
}

func parseReleaseVersion(value string) ([3]int, error) {
	var parsed [3]int
	if _, err := fmt.Sscanf(value, "v%d.%d.%d", &parsed[0], &parsed[1], &parsed[2]); err != nil ||
		fmt.Sprintf("v%d.%d.%d", parsed[0], parsed[1], parsed[2]) != value ||
		parsed[0] < 0 || parsed[1] < 0 || parsed[2] < 0 {
		return parsed, fmt.Errorf("must use exact vMAJOR.MINOR.PATCH form, got %q", value)
	}
	return parsed, nil
}

func releaseAtLeast(version, minimum string) (bool, error) {
	got, err := parseReleaseVersion(version)
	if err != nil {
		return false, err
	}
	want, err := parseReleaseVersion(minimum)
	if err != nil {
		return false, err
	}
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i], nil
		}
	}
	return true, nil
}

func matchedRuleIDs(results []domain.RuleResult) []string {
	ids := make([]string, 0, len(results))
	for _, result := range results {
		if result.Matched {
			ids = append(ids, result.RuleID)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestMatchedRuleIDsIncludesOnlyMatchedRulesAndPreservesDuplicates(t *testing.T) {
	results := []domain.RuleResult{
		{RuleID: "rule-b", Matched: true},
		{RuleID: "ignored", Matched: false},
		{RuleID: "rule-a", Matched: true},
		{RuleID: "rule-a", Matched: true},
	}
	want := []string{"rule-a", "rule-a", "rule-b"}
	if got := matchedRuleIDs(results); !slices.Equal(got, want) {
		t.Fatalf("matchedRuleIDs() = %q, want %q", got, want)
	}
}

// TestConformanceCompleteness makes the corpus an executable compatibility
// surface rather than a bag of examples. It pins every reachable outcome of
// every shipped policy, every generic condition operator and logical branch,
// every reversibility class, and the irreversibility floor's worst-wins
// composition guarantee.
func TestConformanceCompleteness(t *testing.T) {
	policyFiles, err := filepath.Glob(filepath.Join("..", "..", "policies", "*.yaml"))
	if err != nil {
		t.Fatalf("glob policies: %v", err)
	}
	if len(policyFiles) == 0 {
		t.Fatal("no shipped policies found under policies/")
	}

	caseFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "conformance", "*.json"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}
	const minimumCases = 60
	if len(caseFiles) < minimumCases {
		t.Errorf("conformance corpus has %d cases, want at least %d", len(caseFiles), minimumCases)
	}

	shippedDir := filepath.Clean(filepath.Join("..", "..", "policies"))
	shippedPolicies := make(map[string]domain.Policy, len(policyFiles))
	for _, file := range policyFiles {
		policy, err := policyload.Load(file)
		if err != nil {
			t.Fatalf("load shipped policy %s: %v", filepath.Base(file), err)
		}
		if err := engine.ValidatePolicy(&policy); err != nil {
			t.Fatalf("shipped policy %s fails validation: %v", filepath.Base(file), err)
		}
		shippedPolicies[filepath.Base(file)] = policy
	}

	coveredOutcomes := map[string]map[string]struct{}{}
	seenNames := map[string]string{}
	coveredOperators := map[string]struct{}{}
	coveredLogical := map[string]struct{}{}
	coveredModes := map[string]struct{}{}
	coveredReversibility := map[engine.ReversibilityClass]struct{}{}
	floorOverridePinned := false
	for _, file := range caseFiles {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read case %s: %v", file, err)
		}
		c, err := decodeConformanceCase(raw)
		if err != nil {
			t.Fatalf("parse case %s: %v", file, err)
		}
		if err := registerConformanceCaseName(seenNames, c.Name, filepath.Base(file)); err != nil {
			t.Error(err)
		}
		if want := strings.TrimSuffix(filepath.Base(file), ".json"); c.Name != want {
			t.Errorf("case %s: name %q must match its filename (%q)", filepath.Base(file), c.Name, want)
		}
		coveredModes[c.Mode] = struct{}{}

		policies, err := loadConformancePolicies(file, c)
		if err != nil {
			t.Fatalf("load policies for %s: %v", filepath.Base(file), err)
		}
		result := evaluateConformanceCase(c, policies)
		if got := string(result.Decision); got != c.Expect.Decision {
			t.Errorf("case %s: actual decision %q does not match expected %q", filepath.Base(file), got, c.Expect.Decision)
		}
		if got := string(result.ActionTaken); got != c.Expect.ActionTaken {
			t.Errorf("case %s: actual action %q does not match expected %q", filepath.Base(file), got, c.Expect.ActionTaken)
		}

		paths, err := c.policyPaths()
		if err != nil {
			t.Fatalf("policy paths for %s: %v", filepath.Base(file), err)
		}
		hasFloor := false
		for i, path := range paths {
			// Credit outcome coverage only when the reference resolves to the
			// shipped policies directory. A same-named fixture cannot satisfy it.
			resolved := filepath.Clean(filepath.Join(filepath.Dir(file), path))
			if filepath.Dir(resolved) != shippedDir {
				continue
			}
			base := filepath.Base(resolved)
			if coveredOutcomes[base] == nil {
				coveredOutcomes[base] = map[string]struct{}{}
			}
			// Attribute an outcome to this shipped policy alone. In a
			// multi-policy case, the aggregate result may have been caused by
			// another policy and must not create false coverage.
			policyResult := evaluateConformanceCase(c, []domain.Policy{policies[i]})
			coveredOutcomes[base][string(policyResult.Decision)] = struct{}{}
			if base == "irreversibility_floor.yaml" {
				hasFloor = true
			}
		}

		for _, ruleResult := range result.RuleResults {
			if !ruleResult.Matched {
				continue
			}
			for _, policy := range policies {
				if policy.PolicyID != ruleResult.PolicyID {
					continue
				}
				for _, rule := range policy.Rules {
					if rule.RuleID == ruleResult.RuleID {
						collectConditionCoverage(rule.Conditions, coveredOperators, coveredLogical)
					}
				}
			}
		}

		if hasFloor {
			class := engine.ClassifyReversibility(c.Envelope)
			coveredReversibility[class] = struct{}{}
			if len(policies) > 1 && class == engine.Irreversible && result.Decision == domain.DecisionEscalated {
				matchedAllow := false
				matchedFloorEscalation := false
				for _, ruleResult := range result.RuleResults {
					if !ruleResult.Matched {
						continue
					}
					matchedAllow = matchedAllow || ruleResult.Effect == domain.EffectAllow
					matchedFloorEscalation = matchedFloorEscalation ||
						(ruleResult.PolicyID == "irreversibility-floor" && ruleResult.RuleID == "rule-irreversible-escalate")
				}
				floorOverridePinned = floorOverridePinned || (matchedAllow && matchedFloorEscalation)
			}
		}
	}

	for base, policy := range shippedPolicies {
		missing := missingPolicyOutcomes(policy, coveredOutcomes[base])
		if len(missing) > 0 {
			t.Errorf("shipped policy %s lacks conformance outcomes %v", base, missing)
		}
	}

	for operator := range knownOperators {
		if _, ok := coveredOperators[operator]; !ok {
			t.Errorf("condition operator %q has no matched conformance case", operator)
		}
	}
	for _, logical := range []string{"and", "or", "not"} {
		if _, ok := coveredLogical[logical]; !ok {
			t.Errorf("logical condition %q has no matched conformance case", logical)
		}
	}
	for _, mode := range []string{string(domain.PolicyModeEnforcement), string(domain.PolicyModeShadow)} {
		if _, ok := coveredModes[mode]; !ok {
			t.Errorf("policy mode %q has no conformance case", mode)
		}
	}
	for _, class := range []engine.ReversibilityClass{
		engine.Reversible, engine.Recoverable, engine.Irreversible, engine.Unknown,
	} {
		if _, ok := coveredReversibility[class]; !ok {
			t.Errorf("reversibility class %q has no irreversibility-floor conformance case", class)
		}
	}
	if !floorOverridePinned {
		t.Error("no multi-policy case proves an irreversible floor escalation outranks a matched allow rule")
	}
}

func registerConformanceCaseName(seen map[string]string, name, file string) error {
	if previous, duplicate := seen[name]; duplicate {
		return fmt.Errorf("duplicate case name %q in %s (already used by %s)", name, file, previous)
	}
	seen[name] = file
	return nil
}

func TestRegisterConformanceCaseNameRejectsDuplicates(t *testing.T) {
	seen := map[string]string{}
	if err := registerConformanceCaseName(seen, "same-id", "first.json"); err != nil {
		t.Fatalf("register first case ID: %v", err)
	}
	if err := registerConformanceCaseName(seen, "same-id", "second.json"); err == nil {
		t.Fatal("duplicate case ID was accepted")
	}
}

func missingPolicyOutcomes(policy domain.Policy, covered map[string]struct{}) []string {
	expected := map[string]struct{}{string(domain.DecisionAllowed): {}}
	for _, rule := range policy.Rules {
		if !rule.IsEnabled() {
			continue
		}
		switch rule.Effect {
		case domain.EffectAllow:
			expected[string(domain.DecisionAllowed)] = struct{}{}
		case domain.EffectFlag:
			expected[string(domain.DecisionFlagged)] = struct{}{}
		case domain.EffectEscalate:
			expected[string(domain.DecisionEscalated)] = struct{}{}
		case domain.EffectDeny:
			expected[string(domain.DecisionDenied)] = struct{}{}
		}
	}
	missing := make([]string, 0, len(expected))
	for outcome := range expected {
		if _, ok := covered[outcome]; !ok {
			missing = append(missing, outcome)
		}
	}
	slices.Sort(missing)
	return missing
}

func collectConditionCoverage(condition domain.Condition, operators, logical map[string]struct{}) {
	if len(condition.And) > 0 {
		logical["and"] = struct{}{}
		for _, child := range condition.And {
			collectConditionCoverage(child, operators, logical)
		}
	}
	if len(condition.Or) > 0 {
		logical["or"] = struct{}{}
		for _, child := range condition.Or {
			collectConditionCoverage(child, operators, logical)
		}
	}
	if condition.Not != nil {
		logical["not"] = struct{}{}
		collectConditionCoverage(*condition.Not, operators, logical)
	}
	if condition.Operator != "" {
		operators[string(condition.Operator)] = struct{}{}
	}
}
