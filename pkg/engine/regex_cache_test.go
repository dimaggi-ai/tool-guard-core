package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestPrewarmRegexCache_PopulatesAcrossConditionShapes drives the
// recursive walker through every branch that holds a regex: leaf at the
// top level, leaves nested in and/or/not, and shell_classify's
// argv_pattern_deny. Confirms the cache size grew by at least the
// number of distinct patterns supplied.
func TestPrewarmRegexCache_PopulatesAcrossConditionShapes(t *testing.T) {
	before := CachedRegexCount()

	notLeaf := domain.Condition{
		Field:    "x",
		Operator: domain.OpRegex,
		Value:    "^prewarm_not_[a-z]+$",
	}
	policies := []domain.Policy{{
		Rules: []domain.Rule{{
			Conditions: domain.Condition{
				And: []domain.Condition{
					{Field: "a", Operator: domain.OpRegex, Value: "^prewarm_and_\\d+$"},
					{Or: []domain.Condition{
						{Field: "b", Operator: domain.OpRegex, Value: "prewarm_or_alt_[ab]"},
					}},
					{Not: &notLeaf},
				},
			},
		}, {
			Conditions: domain.Condition{
				ShellClassify: &domain.ShellClassify{
					Require: domain.ShellRequire{
						ArgvDenyPatterns: []string{
							`^prewarm_argv_[A-Z]+$`,
							`^prewarm_argv_\d{2,4}$`,
						},
					},
				},
			},
		}},
	}}

	PrewarmRegexCache(policies)

	after := CachedRegexCount()
	grew := after - before
	// 1 (and-leaf) + 1 (or-leaf) + 1 (not-leaf) + 2 (shell argv) = 5
	if grew < 5 {
		t.Fatalf("expected cache to grow by ≥5 entries after prewarm; before=%d after=%d", before, after)
	}

	// A non-regex leaf must not poison the cache (e.g. an `eq` rule on a
	// number-shaped value should be silently skipped).
	pre := CachedRegexCount()
	PrewarmRegexCache([]domain.Policy{{
		Rules: []domain.Rule{{
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
		}},
	}})
	if CachedRegexCount() != pre {
		t.Errorf("non-regex leaves must not enter the regex cache; before=%d after=%d", pre, CachedRegexCount())
	}
}

// TestEvalSQLClassify_BoolWrapper drives the legacy bool-only wrapper to
// make sure the With/no-With paths agree. evalSQLClassify is the
// non-detail wrapper used by callers that don't care about the reason
// string; we keep it covered so a refactor that desyncs the two
// definitions trips a test.
func TestEvalSQLClassify_BoolWrapper(t *testing.T) {
	s := &domain.SQLClassify{
		Field:   "parameters.sql",
		Dialect: "postgres",
		Require: domain.SQLRequire{
			TopLevelKinds: []string{"SELECT"},
		},
	}
	fields := map[string]interface{}{
		"parameters.sql": "DELETE FROM users",
	}
	if !evalSQLClassify(s, fields) {
		t.Errorf("DELETE under top_level_kinds=[SELECT] should fire the wrapper")
	}
	fields["parameters.sql"] = "SELECT 1"
	if evalSQLClassify(s, fields) {
		t.Errorf("clean SELECT under top_level_kinds=[SELECT] should NOT fire the wrapper")
	}
}
