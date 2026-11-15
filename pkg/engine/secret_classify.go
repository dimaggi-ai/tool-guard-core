package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

const defaultSecretMaxBytes = 64 * 1024
const maximumSecretMaxBytes = 1024 * 1024

type secretRule struct {
	ID, Pattern string
	Keywords    []string
	SecretGroup int
	Entropy     float64
	Path        string
	Allowlists  []secretAllowlist
}

type secretAllowlist struct {
	Condition, RegexTarget    string
	Regexes, Stopwords, Paths []string
}

type secretFinding struct{ RuleID, Class string }
type secretResult struct {
	Findings     []secretFinding
	Truncated    bool
	ScannedBytes int
}

type compiledSecretRule struct {
	secretRule
	re     *regexp.Regexp
	allows []compiledSecretAllowlist
}
type compiledSecretAllowlist struct {
	secretAllowlist
	regexes []*regexp.Regexp
}

// Generated data is immutable. Compile once, including for direct Go callers.
type secretRuleSet struct {
	rules  []compiledSecretRule
	global []compiledSecretAllowlist
}

func loadSecretRules() ([]compiledSecretRule, []compiledSecretAllowlist, error) {
	set, err := compiledSecretRules()
	return set.rules, set.global, err
}

var compiledSecretRules = sync.OnceValues(func() (secretRuleSet, error) {
	compileAllows := func(raw []secretAllowlist) ([]compiledSecretAllowlist, error) {
		out := make([]compiledSecretAllowlist, 0, len(raw))
		for _, a := range raw {
			c := compiledSecretAllowlist{secretAllowlist: a}
			for _, pattern := range a.Regexes {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, err
				}
				c.regexes = append(c.regexes, re)
			}
			out = append(out, c)
		}
		return out, nil
	}
	global, err := compileAllows(secretGlobalAllowlists)
	if err != nil {
		return secretRuleSet{}, err
	}
	out := make([]compiledSecretRule, 0, len(secretRules))
	for _, r := range secretRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return secretRuleSet{}, fmt.Errorf("%s: %w", r.ID, err)
		}
		if r.SecretGroup < 0 || r.SecretGroup > re.NumSubexp() {
			return secretRuleSet{}, fmt.Errorf("%s: invalid secret group", r.ID)
		}
		allows, err := compileAllows(r.Allowlists)
		if err != nil {
			return secretRuleSet{}, fmt.Errorf("%s: %w", r.ID, err)
		}
		out = append(out, compiledSecretRule{r, re, allows})
	}
	return secretRuleSet{out, global}, nil
})

func validateSecretClassify(c *domain.SecretClassify) error {
	if strings.TrimSpace(c.Field) == "" {
		return fmt.Errorf("field is required")
	}
	if len(c.Classes) == 0 {
		return fmt.Errorf("classes must contain provider or generic")
	}
	seen := map[string]bool{}
	for _, class := range c.Classes {
		if class != "provider" && class != "generic" {
			return fmt.Errorf("unknown class %q", class)
		}
		if seen[class] {
			return fmt.Errorf("duplicate class %q", class)
		}
		seen[class] = true
	}
	if c.MaxBytes < 0 || c.MaxBytes > maximumSecretMaxBytes {
		return fmt.Errorf("max_bytes must be between 0 and %d", maximumSecretMaxBytes)
	}
	for _, id := range c.ExcludeRules {
		if !slices.ContainsFunc(secretRules, func(r secretRule) bool { return r.ID == id }) {
			return fmt.Errorf("unknown excluded rule %q", id)
		}
	}
	_, _, err := loadSecretRules()
	return err
}

func evalSecretClassifyWithDetail(c *domain.SecretClassify, fields map[string]interface{}) (bool, string) {
	if err := validateSecretClassify(c); err != nil {
		return true, "secret_classify: invalid configuration: " + err.Error()
	}
	raw, ok := resolveField(c.Field, fields)
	if !ok || raw == nil {
		return true, "secret_classify: field is missing or null"
	}
	var text string
	switch value := raw.(type) {
	case string:
		text = value
	case []interface{}, map[string]interface{}, []string:
		encoded, err := json.Marshal(value)
		if err != nil {
			return true, "secret_classify: field cannot be encoded as JSON"
		}
		text = string(encoded)
	default:
		return true, "secret_classify: field must be text, an array, or an object"
	}
	result := classifySecrets(text, c.MaxBytes)
	ids := []string{}
	for _, f := range result.Findings {
		if slices.Contains(c.Classes, f.Class) && !slices.Contains(c.ExcludeRules, f.RuleID) {
			ids = append(ids, f.RuleID)
		}
	}
	// Diagnostics contain rule IDs and scan metadata, never captured values.
	detail := fmt.Sprintf("secret_classify: rules=%s scanned_bytes=%d truncated=%t", strings.Join(ids, ","), result.ScannedBytes, result.Truncated)
	return len(ids) > 0, detail
}

func classifySecrets(text string, maxBytes int) secretResult {
	if maxBytes <= 0 {
		maxBytes = defaultSecretMaxBytes
	}
	if maxBytes > maximumSecretMaxBytes {
		maxBytes = maximumSecretMaxBytes
	}
	result := secretResult{Truncated: len(text) > maxBytes}
	if result.Truncated {
		text = text[:maxBytes]
	}
	result.ScannedBytes = len(text)
	rules, global, err := loadSecretRules()
	if err != nil {
		panic(err)
	} // Generated-data errors are rejected at policy validation.
	lower := strings.ToLower(text)
	newlines, breaks := secretLineBreaks(text)
	type candidate struct {
		id, secret string
		line       int
	}
	var candidates []candidate
	// A line-target allowlist regex gives the same answer for every match on
	// one line. Caching it by line offsets keeps a long line with many
	// matches from being rescanned once per match.
	type lineRegexKey struct {
		re         *regexp.Regexp
		start, end int
	}
	lineHits := map[lineRegexKey]bool{}
	for _, r := range rules {
		if r.Path != "" || (len(r.Keywords) > 0 && !containsSecretKeyword(lower, r.Keywords)) {
			continue
		}
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			match := strings.Trim(text[loc[0]:loc[1]], "\n")
			secret := match
			groups := r.re.FindStringSubmatch(match)
			if len(groups) >= 2 {
				if r.SecretGroup > 0 {
					secret = groups[r.SecretGroup]
				} else {
					for _, group := range groups[1:] {
						if group != "" {
							secret = group
							break
						}
					}
				}
			}
			if r.Entropy != 0 && secretEntropy(secret) <= r.Entropy {
				continue
			}
			lineStart, lineEnd, lineNumber := secretMatchLineSpan(text, newlines, breaks, loc[0], loc[0]+len(match))
			line := text[lineStart:lineEnd]
			lineMatch := func(re *regexp.Regexp) bool {
				key := lineRegexKey{re, lineStart, lineEnd}
				hit, ok := lineHits[key]
				if !ok {
					hit = re.MatchString(line)
					lineHits[key] = hit
				}
				return hit
			}
			if secretAllowed(global, secret, match, line, lineMatch) || secretAllowed(r.allows, secret, match, line, lineMatch) {
				continue
			}
			candidates = append(candidates, candidate{r.ID, secret, lineNumber})
		}
	}
	// Index provider findings by line once, so suppressing generic findings
	// does not compare every candidate with every other one.
	providerByLine := map[int][]string{}
	for _, c := range candidates {
		if c.id != "generic-api-key" {
			providerByLine[c.line] = append(providerByLine[c.line], c.secret)
		}
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.id] {
			continue
		}
		class := "provider"
		if c.id == "generic-api-key" {
			class = "generic"
			// Upstream suppresses generic findings contained in a provider
			// finding on the same line. Independent generic findings remain.
			if slices.ContainsFunc(providerByLine[c.line], func(other string) bool {
				return strings.Contains(other, c.secret)
			}) {
				continue
			}
		}
		seen[c.id] = true
		result.Findings = append(result.Findings, secretFinding{c.id, class})
	}
	return result
}

// Preserve gitleaks v8.30.1 detect/location.go line boundaries, including its
// unterminated-last-line behavior: that line's allowlist context starts at 0.
// Upstream copyright Zachary Rice; MIT license: third_party/gitleaks/LICENSE.
func secretMatchLine(text string, newlines []int, start, end int) (string, int) {
	_, breaks := secretLineBreaks(text)
	lineStart, lineEnd, number := secretMatchLineSpan(text, newlines, breaks, start, end)
	return text[lineStart:lineEnd], number
}

// secretLineBreaks returns the offsets of every '\n', and of every '\n' or
// '\r', in text.
func secretLineBreaks(text string) (newlines, breaks []int) {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\n':
			newlines = append(newlines, i)
			breaks = append(breaks, i)
		case '\r':
			breaks = append(breaks, i)
		}
	}
	return newlines, breaks
}

// secretMatchLineSpan returns the offsets of secretMatchLine's line and its
// number. breaks holds the offsets of every '\n' or '\r' in text.
func secretMatchLineSpan(text string, newlines, breaks []int, start, end int) (int, int, int) {
	if len(newlines) == 0 {
		newlines = []int{len(text)}
	}
	// Line k spans [newlines[k-1], newlines[k]); line 0 starts at 0. Binary
	// search keeps each lookup O(log lines) instead of a scan of every line.
	previous := func(k int) int {
		if k == 0 {
			return 0
		}
		return newlines[k-1]
	}
	n := len(newlines)
	i := sort.Search(n, func(k int) bool { return newlines[k] > start })
	lineSet := i < n
	lineStart, lineEnd, startLine := 0, 0, 0
	if lineSet {
		startLine, lineStart, lineEnd = i, previous(i), newlines[i]
	}
	if j := sort.Search(n, func(k int) bool { return newlines[k] >= end }); j < n && previous(j) < end && (!lineSet || j >= i) {
		lineEnd = newlines[j]
	}
	if !lineSet {
		// The last line runs from end to the next '\n' or '\r', or to the end
		// of text. A binary search keeps this from rescanning the line for
		// every match on it.
		startLine = n
		lineEnd = len(text)
		if k := sort.SearchInts(breaks, end); k < len(breaks) {
			lineEnd = breaks[k]
		}
	}
	if end > lineEnd {
		lineEnd = end
	}
	return lineStart, lineEnd, startLine
}

func containsSecretKeyword(lower string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// Match gitleaks v8.30.1: rune counts divided by byte length, strict > limit.
func secretEntropy(secret string) float64 {
	counts := map[rune]int{}
	for _, r := range secret {
		counts[r]++
	}
	var entropy float64
	for _, count := range counts {
		frequency := float64(count) / float64(len(secret))
		entropy -= frequency * math.Log2(frequency)
	}
	return entropy
}

// lineMatch, when not nil, answers a regex against line; the caller uses it
// to cache answers for one line.
func secretAllowed(allows []compiledSecretAllowlist, secret, match, line string, lineMatch func(*regexp.Regexp) bool) bool {
	for _, a := range allows {
		// Text-only calls have no path. An AND with paths cannot match.
		if a.Condition == "AND" && len(a.Paths) > 0 {
			continue
		}
		target := secret
		switch a.RegexTarget {
		case "match":
			target = match
		case "line":
			target = line
		}
		matchTarget := func(re *regexp.Regexp) bool { return re.MatchString(target) }
		if a.RegexTarget == "line" && lineMatch != nil {
			matchTarget = lineMatch
		}
		regexMatch := target != "" && slices.ContainsFunc(a.regexes, matchTarget)
		wordMatch := secret != "" && containsSecretKeyword(strings.ToLower(secret), a.Stopwords)
		if a.Condition == "AND" {
			if (len(a.Regexes) > 0 || len(a.Stopwords) > 0) && (len(a.Regexes) == 0 || regexMatch) && (len(a.Stopwords) == 0 || wordMatch) {
				return true
			}
		} else if regexMatch || wordMatch {
			return true
		}
	}
	return false
}
