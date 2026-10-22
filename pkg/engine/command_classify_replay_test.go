package engine

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// This fixed example replay is not a historical corpus. The real historical
// command corpus is unavailable and its replay remains an open item. Baseline
// provenance and the absence of a shipped gh regex are recorded in the fixture.
func TestCommandClassify_FixedExampleReplay(t *testing.T) {
	data, err := os.ReadFile("../../testdata/command-classify-replay.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Baseline string `json:"baseline_commit"`
		OldRegex string `json:"old_regex"`
		Cases    []struct {
			Command string `json:"command"`
			Source  string `json:"source"`
			Old     bool   `json:"old_regex_match"`
			New     bool   `json:"new_match"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Baseline != "8d45152" || len(fixture.Cases) == 0 {
		t.Fatal("missing fixed baseline")
	}
	old := regexp.MustCompile(fixture.OldRegex)
	cond := domain.Condition{CommandClassify: &domain.CommandClassify{Field: "command", Profile: "gh_read"}}
	for _, tc := range fixture.Cases {
		t.Run(tc.Command, func(t *testing.T) {
			if tc.Source == "" {
				t.Fatal("missing source attribution")
			}
			if got := old.MatchString(tc.Command); got != tc.Old {
				t.Errorf("old regex match=%v, want %v", got, tc.Old)
			}
			got, detail := EvalConditionWithDetail(cond, map[string]interface{}{"command": tc.Command})
			if got != tc.New {
				t.Errorf("new match=%v, want %v: %s", got, tc.New, detail)
			}
			t.Logf("baseline=%s old_regex_match=%v new_match=%v detail=%q", fixture.Baseline, tc.Old, got, detail)
		})
	}
}
