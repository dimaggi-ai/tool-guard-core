package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

// Benchmarks the complete shipped shadow policy, including hand-written rules.
func BenchmarkSecretCommandsPolicy(b *testing.B) {
	policy, err := policyload.Load("../../policies/coding_agent_secret_commands.yaml")
	if err != nil {
		b.Fatal(err)
	}
	if err := engine.ValidatePolicy(&policy); err != nil {
		b.Fatal(err)
	}
	engine.PrewarmRegexCache([]domain.Policy{policy})
	key := "ghp_" + "7Qm4Zv8Lr2Px6Nb9Yk3Jc5Hd1Wf0TsUaEeOi"
	prose := strings.Repeat("Build completed. Tests passed. Document the next release.\n", 1200)
	for _, tc := range []struct{ name, tool, group, field, text, wantRule string }{
		{"note64KB-clean", "write", "filesystem_writes", "content", prose[:65536], ""},
		{"note64KB-secret", "write", "filesystem_writes", "content", prose[:65536-len(key)] + key, "rule-secret-in-agent-note"},
		{"bash-clean", "bash", "shell", "command", "git status --short", ""},
	} {
		b.Run(tc.name, func(b *testing.B) {
			params, err := json.Marshal(map[string]string{tc.field: tc.text, "file_path": "/project/NOTES.md"})
			if err != nil {
				b.Fatal(err)
			}
			envelope := domain.ActionEnvelope{ToolName: tc.tool, ToolGroup: tc.group, Parameters: params}
			evaluator := engine.NewEvaluator()
			check := func() {
				result := evaluator.Evaluate(&envelope, []domain.Policy{policy}, domain.PolicyModeEnforcement)
				matched := false
				for _, rule := range result.RuleResults {
					if rule.Matched && tc.wantRule == "" {
						b.Fatal("clean benchmark unexpectedly matched")
					}
					if rule.Matched && rule.RuleID == tc.wantRule {
						matched = true
					}
				}
				if tc.wantRule != "" && !matched {
					b.Fatal("secret benchmark did not match")
				}
				if result.ActionTaken == domain.ActionDenied || result.ActionTaken == domain.ActionEscalated {
					b.Fatal("shadow policy blocked benchmark")
				}
			}
			check()
			samples := make([]int64, b.N)
			b.SetBytes(int64(len(tc.text)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range samples {
				start := time.Now()
				check()
				samples[i] = time.Since(start).Nanoseconds()
			}
			b.StopTimer()
			slices.Sort(samples)
			b.ReportMetric(float64(samples[(len(samples)-1)*50/100]), "p50-ns")
			b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
		})
	}
}
