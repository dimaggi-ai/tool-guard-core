package engine

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// Construct synthetic fixtures rather than embedding complete credential formats.
func secretTestPAT() string     { return "ghp_" + "7Qm4Zv8Lr2Px6Nb9Yk3Jc5Hd1Wf0TsUaEeOi" }
func secretTestGeneric() string { return "api_key=" + "9Qx7Wm2Zr8Vn4Pk6Hy3Jc5Lf1Td0BsUa" }
func secretTestConfig(classes ...string) *domain.SecretClassify {
	return &domain.SecretClassify{Field: "parameters.content", Classes: classes}
}
func secretTestHas(result secretResult, id string) bool {
	for _, finding := range result.Findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func TestSecretClassifyEntropy(t *testing.T) {
	for _, tt := range []struct {
		text string
		want float64
	}{{"", 0}, {"aaaa", 0}, {"aabb", 1}, {"abcd", 2}, {"é", 0.5}} {
		if got := secretEntropy(tt.text); math.Abs(got-tt.want) > 1e-12 {
			t.Errorf("entropy differs: got %g want %g", got, tt.want)
		}
	}
	if secretTestHas(classifySecrets("ghp_"+strings.Repeat("a", 36), 0), "github-pat") {
		t.Fatal("low entropy provider payload was accepted")
	}
	if !secretTestHas(classifySecrets(secretTestPAT(), 0), "github-pat") {
		t.Fatal("high entropy provider payload was missed")
	}
	// Eight singleton symbols and four doubled symbols have entropy exactly 3.5.
	boundary := "abcdefgh" + "iijjkkll"
	if secretEntropy(boundary) != 3.5 {
		t.Fatal("entropy boundary fixture is invalid")
	}
	if secretTestHas(classifySecrets("api_key="+boundary, 0), "generic-api-key") {
		t.Fatal("entropy equal to the configured threshold must be rejected")
	}
}

func TestSecretClassifyPipeline(t *testing.T) {
	for _, tt := range []struct {
		name, text, id string
		want           bool
	}{
		{"provider", secretTestPAT(), "github-pat", true},
		{"generic", secretTestGeneric(), "generic-api-key", true},
		{"generic low entropy", "api_key=" + strings.Repeat("z", 32), "generic-api-key", false},
		{"match allowlist", "api_version=" + strings.TrimPrefix(secretTestGeneric(), "api_key="), "generic-api-key", false},
		{"line allowlist", "--mount=type=secret,id=thing " + secretTestGeneric(), "generic-api-key", false},
		{"upstream unterminated last line", "--mount=type=secret,id=thing\n" + secretTestGeneric(), "generic-api-key", false},
		{"rule stopword", secretTestGeneric() + "example", "generic-api-key", false},
		{"global stopword", "api_key=" + "abcdefghijklmnopqrstuvwxyz", "generic-api-key", false},
		{"global regex", "api_key=" + "false" + strings.TrimPrefix(secretTestGeneric(), "api_key="), "generic-api-key", false},
		{"path AND cannot exempt text", "LICENSE_key=\"" + strings.TrimPrefix(secretTestGeneric(), "api_key=") + "\"", "generic-api-key", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretTestHas(classifySecrets(tt.text, 0), tt.id); got != tt.want {
				t.Fatalf("rule %s detected=%t want %t", tt.id, got, tt.want)
			}
		})
	}
}

func TestSecretClassifySecretGroupTwo(t *testing.T) {
	// Generic overlap suppression proves Sonar extraction used credential group 2,
	// rather than group 1 (the word "token").
	result := classifySecrets("sonar_token="+"7qm4zv8lr2px6nb9yk3jc5hd1wf0tsuaeeoi6vzx", 0)
	if !secretTestHas(result, "sonar-api-token") {
		t.Fatal("Sonar group-2 provider rule did not match")
	}
	if secretTestHas(result, "generic-api-key") {
		t.Fatal("generic finding was not suppressed by provider group 2")
	}
}

func TestSecretClassifyAllowlists(t *testing.T) {
	for _, tt := range []struct {
		name, condition, target   string
		regexes, stopwords, paths []string
		want                      bool
	}{
		{name: "secret target", regexes: []string{"^payload$"}, want: true},
		{name: "match target", target: "match", regexes: []string{"^key=payload$"}, want: true},
		{name: "line target", target: "line", regexes: []string{"^prefix key=payload suffix$"}, want: true},
		{name: "stopword case insensitive", stopwords: []string{"PAY"}, want: true},
		{name: "AND both match", condition: "AND", regexes: []string{"^payload$"}, stopwords: []string{"load"}, want: true},
		{name: "AND missing stopword", condition: "AND", regexes: []string{"^payload$"}, stopwords: []string{"absent"}},
		{name: "AND missing regex", condition: "AND", regexes: []string{"^absent$"}, stopwords: []string{"load"}},
		{name: "AND path unavailable", condition: "AND", regexes: []string{"payload"}, paths: []string{".*"}},
		{name: "OR path does not suppress regex", regexes: []string{"payload"}, paths: []string{".*"}, want: true},
		{name: "path only unavailable", paths: []string{".*"}},
		{name: "empty AND", condition: "AND"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := compiledSecretAllowlist{secretAllowlist: secretAllowlist{Condition: tt.condition, RegexTarget: tt.target, Regexes: tt.regexes, Stopwords: tt.stopwords, Paths: tt.paths}}
			for _, pattern := range tt.regexes {
				a.regexes = append(a.regexes, regexp.MustCompile(pattern))
			}
			if got := secretAllowed([]compiledSecretAllowlist{a}, "payload", "key=payload", "prefix key=payload suffix"); got != tt.want {
				t.Fatalf("allowed=%t want %t", got, tt.want)
			}
		})
	}
}

func TestSecretClassifyClassesAndExclusion(t *testing.T) {
	for _, tt := range []struct {
		name, text       string
		classes, exclude []string
		want             bool
	}{
		{"provider selected", secretTestPAT(), []string{"provider"}, nil, true},
		{"provider not generic", secretTestPAT(), []string{"generic"}, nil, false},
		{"generic selected", secretTestGeneric(), []string{"generic"}, nil, true},
		{"generic not provider", secretTestGeneric(), []string{"provider"}, nil, false},
		{"provider excluded", secretTestPAT(), []string{"provider"}, []string{"github-pat"}, false},
		{"independent generic survives", secretTestPAT() + "\n" + secretTestGeneric(), []string{"generic"}, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := secretTestConfig(tt.classes...)
			c.ExcludeRules = tt.exclude
			got, detail := evalSecretClassifyWithDetail(c, map[string]interface{}{"parameters.content": tt.text})
			if got != tt.want {
				t.Fatalf("matched=%t want %t; %s", got, tt.want, detail)
			}
			if strings.Contains(detail, secretTestPAT()) || strings.Contains(detail, strings.TrimPrefix(secretTestGeneric(), "api_key=")) {
				t.Fatal("diagnostic exposed synthetic captured value")
			}
		})
	}
}

func TestSecretClassifyCapAndDetail(t *testing.T) {
	token := secretTestPAT()
	capBytes := 128
	for _, tt := range []struct {
		name, text      string
		want, truncated bool
		scanned         int
	}{
		{"at cap", strings.Repeat(" ", capBytes-len(token)) + token, true, false, capBytes},
		{"one byte over", strings.Repeat(" ", capBytes-len(token)+1) + token, false, true, capBytes},
		{"beyond cap", strings.Repeat(" ", capBytes) + token, false, true, capBytes},
		{"short", token, true, false, len(token)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySecrets(tt.text, capBytes)
			if secretTestHas(result, "github-pat") != tt.want || result.Truncated != tt.truncated || result.ScannedBytes != tt.scanned {
				t.Fatalf("cap metadata or detection differs: scanned=%d truncated=%t", result.ScannedBytes, result.Truncated)
			}
			c := secretTestConfig("provider")
			c.MaxBytes = capBytes
			_, detail := evalSecretClassifyWithDetail(c, map[string]interface{}{"parameters.content": tt.text})
			want := "truncated=false"
			if tt.truncated {
				want = "truncated=true"
			}
			if !strings.Contains(detail, want) || !strings.Contains(detail, "scanned_bytes=") || strings.Contains(detail, token) {
				t.Fatal("diagnostic missing metadata or contains captured value")
			}
		})
	}
	if result := classifySecrets(strings.Repeat(" ", defaultSecretMaxBytes)+token, 0); !result.Truncated || result.ScannedBytes != defaultSecretMaxBytes || len(result.Findings) != 0 {
		t.Fatal("default cap was not applied")
	}
}

func TestSecretClassifyMissingAndTypes(t *testing.T) {
	for _, tt := range []struct {
		name   string
		fields map[string]interface{}
		want   bool
	}{
		{"missing", nil, true}, {"null", map[string]interface{}{"parameters.content": nil}, true},
		{"number", map[string]interface{}{"parameters.content": 42}, true}, {"boolean", map[string]interface{}{"parameters.content": false}, true},
		{"unencodable object", map[string]interface{}{"parameters.content": map[string]interface{}{"bad": make(chan int)}}, true},
		{"plain text", map[string]interface{}{"parameters.content": "hello"}, false},
		{"object", map[string]interface{}{"parameters.content": map[string]interface{}{"nested": secretTestPAT()}}, true},
		{"array", map[string]interface{}{"parameters.content": []interface{}{secretTestPAT()}}, true},
		{"string array", map[string]interface{}{"parameters.content": []string{secretTestPAT()}}, true},
		{"nested resolution", map[string]interface{}{"parameters": map[string]interface{}{"content": secretTestPAT()}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := evalSecretClassifyWithDetail(secretTestConfig("provider"), tt.fields); got != tt.want {
				t.Fatalf("matched=%t want %t", got, tt.want)
			}
		})
	}
}

func TestSecretClassifyInvalidConfigFailsClosed(t *testing.T) {
	for _, c := range []*domain.SecretClassify{
		{Classes: []string{"provider"}}, {Field: " ", Classes: []string{"provider"}}, {Field: "parameters.content"},
		{Field: "parameters.content", Classes: []string{"other"}}, {Field: "parameters.content", Classes: []string{"provider", "provider"}},
		{Field: "parameters.content", Classes: []string{"provider"}, MaxBytes: -1}, {Field: "parameters.content", Classes: []string{"provider"}, MaxBytes: maximumSecretMaxBytes + 1},
		{Field: "parameters.content", Classes: []string{"provider"}, ExcludeRules: []string{"not-a-rule"}},
	} {
		if err := validateSecretClassify(c); err == nil {
			t.Error("invalid direct config accepted")
		}
		if got, detail := evalSecretClassifyWithDetail(c, map[string]interface{}{"parameters.content": "hello"}); !got || !strings.Contains(detail, "invalid configuration") {
			t.Error("invalid direct config did not fail closed")
		}
	}
	for _, maxBytes := range []int{0, 1, maximumSecretMaxBytes} {
		c := secretTestConfig("provider", "generic")
		c.MaxBytes = maxBytes
		if err := validateSecretClassify(c); err != nil {
			t.Fatalf("valid cap %d rejected: %v", maxBytes, err)
		}
	}
}

func secretTestEngine(text string) (*Evaluator, *domain.ActionEnvelope, []domain.Policy) {
	params, _ := json.Marshal(map[string]string{"content": text})
	env := &domain.ActionEnvelope{ToolName: "write_file", Parameters: params}
	policy := domain.Policy{PolicyID: "secret-test", Version: 1, Status: domain.PolicyStatusApproved, Mode: domain.PolicyModeEnforcement, Scope: domain.PolicyScope{ToolNames: []string{"write_file"}}, Rules: []domain.Rule{{RuleID: "secrets", Conditions: domain.Condition{SecretClassify: secretTestConfig("provider", "generic")}, Effect: domain.EffectDeny}}}
	return NewEvaluator(), env, []domain.Policy{policy}
}

func TestSecretClassifyEvaluator(t *testing.T) {
	for _, tt := range []struct {
		text string
		want domain.Decision
	}{{"hello", domain.DecisionAllowed}, {secretTestPAT(), domain.DecisionDenied}, {secretTestGeneric(), domain.DecisionDenied}} {
		e, env, policies := secretTestEngine(tt.text)
		result := e.Evaluate(env, policies, domain.PolicyModeEnforcement)
		if result.PoliciesMatched != 1 || result.RulesEvaluated != 1 || result.Decision != tt.want {
			t.Fatalf("evaluator mismatch: matched=%d evaluated=%d decision=%s", result.PoliciesMatched, result.RulesEvaluated, result.Decision)
		}
	}
}

// Reproduce: go test ./pkg/engine -run '^$' -bench '^BenchmarkSecretClassifyEvaluator64KB$' -benchtime=100x -count=3
func BenchmarkSecretClassifyEvaluator64KB(b *testing.B) {
	for _, tt := range []struct {
		name, suffix string
		want         domain.Decision
	}{{"no-secret", "", domain.DecisionAllowed}, {"secret", secretTestPAT(), domain.DecisionDenied}} {
		b.Run(tt.name, func(b *testing.B) {
			text := strings.Repeat(" ", 65536-len(tt.suffix)) + tt.suffix
			e, env, policies := secretTestEngine(text)
			check := func() {
				result := e.Evaluate(env, policies, domain.PolicyModeEnforcement)
				if result.PoliciesMatched != 1 || result.RulesEvaluated != 1 || result.Decision != tt.want {
					b.Fatal("benchmark detection sanity failed")
				}
			}
			check()
			samples := make([]int64, b.N)
			b.SetBytes(65536)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				check()
				samples[i] = time.Since(start).Nanoseconds()
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			if len(samples) > 0 {
				b.ReportMetric(float64(samples[(len(samples)-1)*50/100]), "p50-ns")
				b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
			}
		})
	}
}
