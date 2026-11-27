package mainfloor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// This optional integration test runs the pinned upstream detector. Realistic
// credential-shaped values are constructed in memory, never stored as literals.
func TestSecretDifferentialGitleaks(t *testing.T) {
	binary := os.Getenv("TG_GITLEAKS_BIN")
	if binary == "" {
		t.Skip("set TG_GITLEAKS_BIN to a gitleaks v8.30.1 binary")
	}
	binary, err := exec.LookPath(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	// 1,176 gitleaks runs take about 90 s here and over 4 minutes on a
	// hosted CI runner, so the whole comparison gets 15 minutes.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != "8.30.1" {
		t.Fatalf("require gitleaks 8.30.1; got %q (error %v)", version, err)
	}
	// Isolate the oracle from repository config, ignore files, and environment.
	workdir := t.TempDir()
	config := filepath.Join(workdir, "oracle.toml")
	pinnedConfig, err := os.ReadFile("../../../../third_party/gitleaks/gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, pinnedConfig, 0600); err != nil {
		t.Fatal(err)
	}
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GITLEAKS_") {
			env = append(env, entry)
		}
	}
	cases := differentialDevCases(t)
	rng := rand.New(rand.NewSource(68))
	eligible := map[string]bool{}
	for id, reason := range secretExcludedRules {
		t.Logf("excluded rule=%s reason=%s", id, reason)
	}
	for _, rule := range secretRules {
		if rule.Path != "" || rule.Pattern == "" {
			t.Logf("excluded rule=%s reason=requires file path; classifier accepts text only", rule.ID)
			continue
		}
		eligible[rule.ID] = true
		cases = append(cases, differentialRuleCases(t, rule, rng)...)
	}
	cases = append(cases, differentialAllowlistCases()...)
	results := differentialScan(t, ctx, binary, workdir, config, env, cases)
	covered := map[string]bool{}
	counts := map[string]int{}
	differences := 0
	for i, fixture := range cases {
		upstream := results[i]
		if upstream.err != nil {
			t.Errorf("input=%s: upstream scan failed: %v", fixture.id, upstream.err)
			continue
		}
		want := upstream.ids
		if fixture.target != "" && slices.Contains(want, fixture.target) {
			covered[fixture.target] = true
		}
		got := []string{}
		result := classifySecrets(fixture.text, len(fixture.text)+1)
		if result.Truncated {
			t.Errorf("input=%s: unexpectedly truncated", fixture.id)
		}
		for _, finding := range result.Findings {
			got = append(got, finding.RuleID)
		}
		slices.Sort(got)
		got = slices.Compact(got)
		counts[fixture.kind]++
		if !slices.Equal(got, want) {
			differences++
			// Never print fixture text or matched secret bytes into CI logs.
			t.Errorf("unexplained disagreement input=%s kind=%s classifier=%v gitleaks=%v", fixture.id, fixture.kind, got, want)
		}
	}
	missing := []string{}
	for id := range eligible {
		if !covered[id] {
			missing = append(missing, id)
		}
	}
	slices.Sort(missing)
	t.Logf("gitleaks=8.30.1 inputs=%d dev=%d synthetic=%d negative=%d allowlist=%d rule coverage=%d/%d disagreements=%d", len(cases), counts["dev"], counts["synthetic"], counts["negative"], counts["allowlist"], len(covered), len(eligible), differences)
	t.Log("comparison settings: raw text; recursive decoding disabled; inline gitleaks:allow comments ignored; no path or commit context; no permitted rule-ID disagreements")
	if len(missing) > 0 {
		t.Errorf("synthetic positive coverage gaps (upstream did not detect target rule): %v", missing)
	}
}

type differentialFixture struct {
	id, kind, target, text string
}

type differentialResult struct {
	ids []string
	err error
}

func differentialScan(t *testing.T, ctx context.Context, binary, workdir, config string, env []string, cases []differentialFixture) []differentialResult {
	t.Helper()
	results := make([]differentialResult, len(cases))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				cmd := exec.CommandContext(callCtx, binary, "stdin", "--config", config,
					"--no-banner", "--no-color", "--log-level", "error", "--exit-code", "0",
					"--max-decode-depth", "0", "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", "-")
				cmd.Dir, cmd.Env = workdir, env
				cmd.Stdin = strings.NewReader(cases[i].text)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				cancel()
				if err != nil {
					results[i].err = fmt.Errorf("%w (stderr bytes=%d)", err, stderr.Len())
					continue
				}
				var findings []struct{ RuleID string }
				if err := json.Unmarshal(stdout.Bytes(), &findings); err != nil {
					results[i].err = fmt.Errorf("invalid JSON report: %w", err)
					continue
				}
				for _, finding := range findings {
					results[i].ids = append(results[i].ids, finding.RuleID)
				}
				slices.Sort(results[i].ids)
				results[i].ids = slices.Compact(results[i].ids)
			}
		}()
	}
	for i := range cases {
		jobs <- i
		if i > 0 && i%100 == 0 {
			t.Logf("upstream scan progress: dispatched %d/%d inputs (4 workers)", i+1, len(cases))
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func differentialDevCases(t *testing.T) []differentialFixture {
	t.Helper()
	// Deliberately name the development file; never enumerate its directory.
	file, err := os.Open("../../../../cmd/tg/testdata/secretcommands/dev.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cases := []differentialFixture{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var record struct {
			ID     string         `json:"id"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal([]byte(strings.ReplaceAll(scanner.Text(), "{{+}}", "")), &record); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"command", "content", "new_string", "edits"} {
			value, ok := record.Params[field]
			if !ok {
				continue
			}
			text, ok := value.(string)
			if !ok {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				text = string(encoded)
			}
			cases = append(cases, differentialFixture{id: "dev/" + record.ID + "/" + field, kind: "dev", text: text})
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty development corpus")
	}
	return cases
}

func differentialRuleCases(t *testing.T, rule secretRule, rng *rand.Rand) []differentialFixture {
	t.Helper()
	tree, err := syntax.Parse(rule.Pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("rule=%s: parse regex: %v", rule.ID, err)
	}
	re := regexp.MustCompile(rule.Pattern)
	cases := []differentialFixture{}
	seen := map[string]bool{}
	for attempt := 0; attempt < 200 && len(cases) < 4; attempt++ {
		value := differentialRegexText(tree, rng)
		match := re.FindStringSubmatchIndex(value)
		if match == nil {
			continue // Zero-width boundaries may reject a generated combination.
		}
		lo, hi := differentialSecretSpan(match, rule.SecretGroup)
		if rule.Entropy > 0 && differentialEntropy(value[lo:hi]) <= rule.Entropy {
			continue
		}
		if len(rule.Keywords) > 0 && !slices.ContainsFunc(rule.Keywords, func(k string) bool {
			return strings.Contains(strings.ToLower(value), strings.ToLower(k))
		}) {
			keywords := strings.Join(rule.Keywords, " ")
			if re.MatchString(value + "\n" + keywords) {
				value += "\n" + keywords
			} else if re.MatchString(keywords + "\n" + value) {
				value = keywords + "\n" + value
			} else {
				continue
			}
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		cases = append(cases, differentialFixture{id: fmt.Sprintf("synthetic/%s/%d", rule.ID, len(cases)), kind: "synthetic", target: rule.ID, text: value})
	}
	if len(cases) == 0 {
		t.Errorf("rule=%s: could not generate regex/entropy-valid candidate", rule.ID)
		return nil
	}
	// Preserve provider context while replacing the captured secret with a
	// reference; independently verify the target regex no longer matches.
	value := cases[0].text
	match := re.FindStringSubmatchIndex(value)
	lo, hi := differentialSecretSpan(match, rule.SecretGroup)
	negative := value[:lo] + "${TG_SYNTHETIC_TOKEN}" + value[hi:]
	if re.MatchString(negative) {
		negative = strings.Join(rule.Keywords, " ") + " ${TG_SYNTHETIC_TOKEN}"
	}
	if re.MatchString(negative) {
		t.Errorf("rule=%s: negative fixture unexpectedly matches target regex", rule.ID)
	} else {
		cases = append(cases, differentialFixture{id: "negative/" + rule.ID, kind: "negative", text: negative})
	}
	return cases
}

func differentialSecretSpan(match []int, group int) (int, int) {
	if group > 0 && group*2+1 < len(match) {
		return match[group*2], match[group*2+1]
	}
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] > match[i] {
			return match[i], match[i+1]
		}
	}
	return match[0], match[1]
}

// Generate directly from RE2 syntax so the test never needs checked-in keys.
func differentialRegexText(re *syntax.Regexp, rng *rand.Rand) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCharClass:
		choices := []rune{}
		for r := rune(32); r <= 126; r++ {
			for i := 0; i < len(re.Rune); i += 2 {
				if r >= re.Rune[i] && r <= re.Rune[i+1] {
					choices = append(choices, r)
					break
				}
			}
		}
		if len(choices) > 0 {
			return string(choices[rng.Intn(len(choices))])
		}
		return string(re.Rune[0])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
		return string(alphabet[rng.Intn(len(alphabet))])
	case syntax.OpCapture:
		return differentialRegexText(re.Sub[0], rng)
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			b.WriteString(differentialRegexText(sub, rng))
		}
		return b.String()
	case syntax.OpAlternate:
		return differentialRegexText(re.Sub[rng.Intn(len(re.Sub))], rng)
	case syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		min, max := re.Min, re.Max
		switch re.Op {
		case syntax.OpQuest:
			min, max = 0, 1
		case syntax.OpStar:
			min, max = 0, 16
		case syntax.OpPlus:
			min, max = 1, 17
		}
		if max < 0 || max > min+16 {
			max = min + 16
		}
		n := min + rng.Intn(max-min+1)
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(differentialRegexText(re.Sub[0], rng))
		}
		return b.String()
	default:
		return "" // Anchors and word boundaries consume no text.
	}
}

func differentialEntropy(value string) float64 {
	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(len(value))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func differentialAllowlistCases() []differentialFixture {
	cases := []differentialFixture{}
	for i, value := range []string{
		"$API_TOKEN", "${API_TOKEN}", "${{ secrets.API_TOKEN }}", "{{ api.token }}",
		"%API_TOKEN%", "@API_TOKEN@", "<redacted>", "your-api-key", "changeme",
		strings.Repeat("a", 40), strings.Repeat("X", 40),
		"abcdefghijkl" + "mnopqrstuvwxyz", "/home/example/config/token.txt",
		"014df517-39d1-" + "4453-b7b3-9930c563627c",
	} {
		cases = append(cases, differentialFixture{id: fmt.Sprintf("allowlist/generic/%d", i), kind: "allowlist", text: "api_key = \"" + value + "\""})
	}
	for i, value := range []string{"${PASSWORD}", "password", "changeme", "example", "<password>"} {
		cases = append(cases, differentialFixture{id: fmt.Sprintf("allowlist/curl/%d", i), kind: "allowlist", text: "curl -u admin:" + value + " https://service.invalid"})
	}
	// Verify overlap suppression and the deliberate absence of comment bypasses.
	value := "gh" + "p_" + strings.Repeat("aB3xK9mQ2zR7", 3)
	for i, suffix := range []string{"", " # gitleaks:allow", "\n# gitleaks:allow"} {
		cases = append(cases, differentialFixture{id: fmt.Sprintf("allowlist/overlap-comment/%d", i), kind: "allowlist", text: "api_key = \"" + value + "\"" + suffix})
	}
	generic := "9Qx7Wm2Zr8Vn4Pk6" + "Hy3Jc5Lf1Td0BsUa"
	assignment := "api_key=" + generic
	for _, probe := range []struct{ name, text string }{
		{"generic-baseline", assignment},
		{"generic-match", "api_version=" + generic},
		{"generic-rule-stopword", assignment + "example"},
		{"generic-global-regex", "api_key=false" + generic},
		{"generic-path-and-no-path", "LICENSE_key=\"" + generic + "\""},
		{"line-same", "--mount=type=secret,id=thing " + assignment},
		{"line-previous", "--mount=type=secret,id=thing\n" + assignment},
		{"line-next", assignment + "\n--mount=type=secret,id=thing"},
		{"line-leading-newline", "\n--mount=type=secret,id=thing " + assignment},
		{"line-trailing-newline", "--mount=type=secret,id=thing " + assignment + "\n"},
		{"line-surrounded-newlines", "\n--mount=type=secret,id=thing " + assignment + "\n"},
		{"generic-leading-newline", "\n" + assignment},
		{"generic-trailing-newline", assignment + "\n"},
		{"generic-surrounded-newlines", "\n" + assignment + "\n"},
	} {
		cases = append(cases, differentialFixture{id: "allowlist/" + probe.name, kind: "allowlist", text: probe.text})
	}
	return cases
}
