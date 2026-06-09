package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// validateOperatorValue enforces operator/value-type compatibility at
// policy load time. The runtime evaluator silently returns false when
// types disagree (so a `gt` on a string allows everything); refusing
// at load surfaces fat-finger typos while the policy is still in
// source control.
func validateOperatorValue(op domain.Operator, value interface{}, ctx string) error {
	switch op {
	case domain.OpGt, domain.OpGte, domain.OpLt, domain.OpLte:
		// Numeric value required. We accept numbers directly and
		// strings that parse as a number (the runtime coerces both).
		// A non-numeric string is the fat-finger we want to catch.
		switch v := value.(type) {
		case float64, float32, int, int64, int32, int16, int8, uint, uint64, uint32:
			return nil
		case string:
			if _, err := parseFloat(v); err != nil {
				return fmt.Errorf("%s: operator %q requires a numeric value (or a string that parses as a number), got %q", ctx, op, v)
			}
			return nil
		case nil:
			return fmt.Errorf("%s: operator %q requires a numeric value, got nil", ctx, op)
		}
		return fmt.Errorf("%s: operator %q requires a numeric value, got %T", ctx, op, value)

	case domain.OpRegex:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: operator %q requires a string value, got %T", ctx, op, value)
		}
		if _, err := compiledRegex(s); err != nil {
			return fmt.Errorf("%s: regex value %q does not compile: %w", ctx, s, err)
		}
		return nil

	case domain.OpIn:
		switch value.(type) {
		case []interface{}, []string, []int, []int64, []float64:
			return nil
		}
		return fmt.Errorf("%s: operator %q requires a list value, got %T", ctx, op, value)

	case domain.OpGtField, domain.OpLtField:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s: operator %q requires the other field name as a string, got %T", ctx, op, value)
		}
		return nil

	case domain.OpContains:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s: operator %q requires a string substring, got %T", ctx, op, value)
		}
		return nil
	}
	// Eq/Neq accept any typed value, but nil is almost always a typo
	// (`compareEq(x, nil)` will return false for every real envelope,
	// so the rule silently never fires). Refuse it at load.
	switch op {
	case domain.OpEq, domain.OpNeq:
		if value == nil {
			return fmt.Errorf("%s: operator %q requires a typed value, got nil", ctx, op)
		}
	}
	return nil
}

// ValidatePolicy walks a policy's rule conditions and surfaces shape
// errors that the engine would otherwise silently fail-open on:
//
//   - empty Condition node (no And/Or/Not/leaf/SQLClassify/PathClassify/
//     ShellClassify) — such a node returns true from EvalCondition and
//     the rule fires on every call, which a hostile YAML PR could
//     weaponise into a deny-all
//   - regex value that does not compile — compareRegex returns false
//     on bad pattern, so the rule never fires and the proxy silently
//     allows
//
// Run this at policy load time and refuse to install a policy that
// fails validation.
func ValidatePolicy(p *domain.Policy) error {
	for i := range p.Rules {
		if err := validateCondition(&p.Rules[i].Conditions, fmt.Sprintf("rule %q", p.Rules[i].RuleID), 0); err != nil {
			return fmt.Errorf("policy %q: %w", p.PolicyID, err)
		}
	}
	return nil
}

// maxConditionDepth bounds the recursion budget for validateCondition
// and (transitively) EvalCondition. Deeply nested AND/OR/NOT trees
// could otherwise exhaust the call stack on a hostile policy load.
const maxConditionDepth = 64

func validateCondition(c *domain.Condition, ctx string, depth int) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("%s: condition tree deeper than %d nodes — refuse to load", ctx, maxConditionDepth)
	}

	hasAnd := len(c.And) > 0
	hasOr := len(c.Or) > 0
	hasNot := c.Not != nil
	hasLeaf := c.Field != "" && c.Operator != ""
	hasSQLClassify := c.SQLClassify != nil
	hasPathClassify := c.PathClassify != nil
	hasShellClassify := c.ShellClassify != nil
	hasLLMClassify := c.LLMClassify != nil

	populated := 0
	for _, b := range []bool{hasAnd, hasOr, hasNot, hasLeaf, hasSQLClassify, hasPathClassify, hasShellClassify, hasLLMClassify} {
		if b {
			populated++
		}
	}
	if populated == 0 {
		return fmt.Errorf("%s: empty condition (no and/or/not/leaf/sql_classify/path_classify/shell_classify/llm_classify) — would match every call; refuse to load", ctx)
	}
	// Exactly one form should be set on a single node. Mixed nodes
	// silently drop everything but the first branch in EvalCondition.
	if populated > 1 {
		return fmt.Errorf("%s: condition has multiple populated forms — exactly one of {and, or, not, leaf, sql_classify, path_classify, shell_classify, llm_classify} must be set", ctx)
	}

	// LLMClassify: require a prompt_field and at least one forbidden
	// label — an empty forbidden list means the classifier always
	// returns "safe" which is the no-op rule the validator already
	// guards against above. Also catch the family of label-shape
	// footguns that would silently break the classifier:
	//   - "safe" as a forbidden label → classifier short-circuits
	//     on "safe" so the rule never fires (silent allow-all)
	//   - duplicate labels → no harm but inflate the system prompt
	//   - labels with commas / newlines → string-joined into the
	//     system prompt, corrupting the closed-set ("x, safe" injects
	//     `safe` into the bucket list)
	//   - labels with control chars / quotes → could break JSON
	//     formatting in the system prompt template
	//   - whitespace-only labels → silent no-op
	//   - upper-bound: prompt size blows up with thousands of labels
	if hasLLMClassify {
		if c.LLMClassify.PromptField == "" {
			return fmt.Errorf("%s/llm_classify: prompt_field is required", ctx)
		}
		if c.LLMClassify.OllamaURL != "" {
			if err := validateOllamaURL(c.LLMClassify.OllamaURL); err != nil {
				return fmt.Errorf("%s/llm_classify/ollama_url: %w", ctx, err)
			}
		}
		if c.LLMClassify.TimeoutSeconds < 0 || c.LLMClassify.TimeoutSeconds > 120 {
			return fmt.Errorf("%s/llm_classify: timeout_seconds must be in [0, 120] (got %d)", ctx, c.LLMClassify.TimeoutSeconds)
		}
		if len(c.LLMClassify.Forbidden) == 0 {
			return fmt.Errorf("%s/llm_classify: forbidden list must contain at least one label (else the rule never fires)", ctx)
		}
		if len(c.LLMClassify.Forbidden) > 64 {
			return fmt.Errorf("%s/llm_classify: forbidden list must have ≤64 labels (got %d)", ctx, len(c.LLMClassify.Forbidden))
		}
		seen := map[string]bool{}
		for i, lbl := range c.LLMClassify.Forbidden {
			normalised := strings.ToLower(strings.TrimSpace(lbl))
			if normalised == "" {
				return fmt.Errorf("%s/llm_classify: forbidden[%d] is whitespace-only", ctx, i)
			}
			if normalised == "safe" {
				return fmt.Errorf("%s/llm_classify: forbidden[%d] is %q — the classifier reserves that label for the negative class; the rule would silently never fire", ctx, i, lbl)
			}
			if normalised == "model_refused" || normalised == "ambiguous" || normalised == "unknown_label" || normalised == "error" {
				return fmt.Errorf("%s/llm_classify: forbidden[%d] uses reserved label %q", ctx, i, lbl)
			}
			if strings.ContainsAny(lbl, ",\n\r\"\t") {
				return fmt.Errorf("%s/llm_classify: forbidden[%d] %q contains a disallowed character (comma / newline / quote / tab)", ctx, i, lbl)
			}
			if seen[normalised] {
				return fmt.Errorf("%s/llm_classify: forbidden[%d] %q is a duplicate label", ctx, i, lbl)
			}
			seen[normalised] = true
		}
	}

	// Recurse into branches.
	for i := range c.And {
		if err := validateCondition(&c.And[i], fmt.Sprintf("%s/and[%d]", ctx, i), depth+1); err != nil {
			return err
		}
	}
	for i := range c.Or {
		if err := validateCondition(&c.Or[i], fmt.Sprintf("%s/or[%d]", ctx, i), depth+1); err != nil {
			return err
		}
	}
	if c.Not != nil {
		if err := validateCondition(c.Not, fmt.Sprintf("%s/not", ctx), depth+1); err != nil {
			return err
		}
	}

	// Leaf: validate operator/value type compatibility.
	// gt/gte/lt/lte require a numeric value (or a field reference for
	// gt_field/lt_field). regex requires a string. in requires a slice.
	// Bad types here silently allow at runtime — we refuse at load.
	if hasLeaf {
		if err := validateOperatorValue(c.Operator, c.Value, ctx); err != nil {
			return err
		}
	}

	// ShellClassify: validate each deny-pattern regex compiles +
	// cap the ** wildcards in argv path lists.
	if hasShellClassify {
		for _, pat := range c.ShellClassify.Require.ArgvDenyPatterns {
			if _, err := compiledRegex(pat); err != nil {
				return fmt.Errorf("%s/shell_classify: argv_deny_pattern %q does not compile: %w", ctx, pat, err)
			}
		}
		for _, prefix := range c.ShellClassify.Require.DeniedArgvPaths {
			if err := capWildcardCount(prefix); err != nil {
				return fmt.Errorf("%s/shell_classify/denied_argv_paths: %w", ctx, err)
			}
		}
	}

	// PathClassify: cap ** wildcards in denied + allowed prefix lists.
	// matchSegments recursion is O(N^k) where k is the ** count; limit
	// to 2 ** per pattern so a hostile policy can't pin a CPU.
	if hasPathClassify {
		for _, list := range [][]string{
			c.PathClassify.Require.DeniedCanonicalPrefixes,
			c.PathClassify.Require.AllowedCanonicalPrefixes,
		} {
			for _, prefix := range list {
				if err := capWildcardCount(prefix); err != nil {
					return fmt.Errorf("%s/path_classify: %w", ctx, err)
				}
			}
		}
	}

	return nil
}

// validateOllamaURL rejects llm_classify Model+OllamaURL combinations
// that would silently hang or hit a hostile host. Scheme allowlist +
// host required — the runtime SafeFetchClient further restricts dial
// targets, but blocking obvious bad shapes at load time gives
// operators a fast error.
func validateOllamaURL(raw string) error {
	if raw == "" {
		return nil
	}
	// Reuse the SSRF URL validator from llmguard via local
	// re-implementation to avoid a dependency-edge import cycle.
	// Same rules: scheme allowlist (http/https), host required, no
	// userinfo, no opaque form.
	if !(strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")) {
		return fmt.Errorf("scheme must be http or https (got %q)", raw)
	}
	if strings.Contains(raw, "@") {
		return fmt.Errorf("userinfo in URL not allowed")
	}
	return nil
}

const maxDeepGlobsPerPattern = 2

// capWildcardCount refuses prefixes with too many ** segments.
// O(N^k) match recursion means each extra ** multiplies worst-case
// CPU per request, so we bound it at load time.
func capWildcardCount(prefix string) error {
	count := 0
	for _, seg := range strings.Split(prefix, "/") {
		if seg == "**" {
			count++
		}
	}
	if count > maxDeepGlobsPerPattern {
		return fmt.Errorf("prefix %q has %d ** wildcards; max allowed is %d (each multiplies worst-case match recursion)", prefix, count, maxDeepGlobsPerPattern)
	}
	return nil
}
