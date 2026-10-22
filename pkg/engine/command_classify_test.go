package engine

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func commandReadCondition() domain.Condition {
	return domain.Condition{CommandClassify: &domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}}
}

func TestCommandClassifyReads(t *testing.T) {
	for _, command := range []string{
		"gh pr view 12",
		"gh pr list --repo o/r",
		"gh issue view 5 -R o/r --json title",
		"gh api repos/o/r/pulls",
		"gh pr checks 3",
		"gh pr diff 3",
		"gh pr view 12 && gh issue view 5",
		"gh pr view 12 --json title | jq .title",
		"gh --repo o/r pr view 12",
		"gh pr --repo o/r view 12",
		"gh pr view 12 --repo=o/r",
		"gh pr view 12 -Ro/r",
		"gh api repos/o/r/pulls -X GET",
		"gh api repos/o/r/pulls -iXGET",
		"gh api '/repos/o/r/issues?a&b' --method=GET",
		"gh pr ls", "gh issue ls", "gh repo ls", "gh release ls",
		"gh pr status", "gh issue status", "gh release view v1",
		"gh api --hostname example.test repos/o/r/pulls --help",
		"gh repo view o/r",
		"gh release list -R o/r",
	} {
		t.Run(command, func(t *testing.T) {
			if got, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": command}); got {
				t.Fatalf("read matched: %q: %s", command, reason)
			}
		})
	}
}

func TestCommandClassifyRejectsUnverifiedCommands(t *testing.T) {
	commands := []string{
		`find . -exec gh pr merge 1 \;`,
		`python3 -c 'import os; os.system("gh pr merge 1")'`,
		"ssh host gh pr merge 1", "flock /tmp/l gh pr merge 1",
		"stdbuf -o0 gh pr merge 1", "setsid gh pr merge 1", "doas gh pr merge 1",
		"su -c 'gh pr merge 1'", "script -qc 'gh pr merge 1' /dev/null",
		"git -c alias.x='!gh pr merge 1' x", "strace -f gh pr merge 1",
		// Literal mentions and configuration paths conservatively escalate too.
		"echo gh", "cat ~/.config/gh/hosts.yml",
		"gh pr --repo X create", "gh pr new", "gh issue new", "gh release -R X delete",
		"gh api repos/o/r/issues -iXPATCH", "gh api repos/o/r/issues -X PATCH", "gh api repos/o/r/issues --method=PATCH",
		"gh api '/repos/o/r/issues?a&b' -X POST",
		"gh api repos/o/r/issues -f title=changed", "gh api repos/o/r/issues -ftitle=changed",
		"gh api repos/o/r/issues -F title=changed", "gh api repos/o/r/issues -Ftitle=changed",
		"gh api repos/o/r/issues --field title=changed", "gh api repos/o/r/issues --field=title=changed",
		"gh api repos/o/r/issues --raw-field title=changed", "gh api repos/o/r/issues --raw-field=title=changed",
		"gh api repos/o/r/issues --input payload.json", "gh api repos/o/r/issues --input=payload.json",
		"gh api repos/o/r/issues -if title=changed", "gh api repos/o/r/issues -iFtitle=changed",
		"gh api repos/o/r/issues -XPOST", "gh api repos/o/r/issues --method POST",
		"gh pr view $(gh pr create)", "echo $(gh pr create)", "echo `gh pr create`",
		"gh pr view 12 <(gh pr create)", "cat <(gh pr create)", "cat >(gh pr create)",
		"(gh pr create)", "{ gh pr create; }", "cat <<EOF\ngh pr create\nEOF",
		"alias gh='gh issue create; :'\ngh pr view 12", "hash -p ./replacement gh; gh pr view 12",
		"export GH_PAGER=unknown; gh pr view 12", "declare GH_HOST=unknown; gh pr view 12",
		"zsh -c 'gh pr create'", "watch gh pr create",
		"eval 'gh pr create'", "sh -c 'gh pr create'", "bash -c 'gh pr create'",
		"env gh pr create", "command gh pr create", "exec gh pr create", "xargs gh pr create",
		"sudo gh pr create", "nohup gh pr create", "time gh pr create",
		"/usr/bin/gh pr view 12", "./gh pr view 12", "'gh' pr view 12", `"gh" pr view 12`,
		`g\h pr view 12`, "$PROGRAM pr view 12", "${PROGRAM} pr view 12",
		"gh pr view $NUMBER", `gh pr view "$NUMBER"`, "gh pr view *", "gh pr view ~",
		"gh pr view '12", "gh pr view 12\\", "GH_HOST=example.test gh pr view 12",
		"gh pr view 12 --unknown", "gh pr unknown", "gh custom-read", "gh alias-read",
		"; gh pr view 12", "& gh pr view 12", "gh pr view 12 ; ; gh issue view 5",
		"gh pr view 12 &&", "| gh pr view 12", "gh pr view 12 || ;",
		"gh", "gh pr", "gh --repo", "gh pr view --repo=", "gh pr view --repo --help",
		"gh api graphql", "gh api /graphql", "gh api https://example.test/repos/o/r/pulls",
		"gh api repos/o/r/issues --method=get", "gh api repos/o/r/issues --include=true",
		"gh pr view 12 > output.txt",
	}
	for _, op := range []string{";", "&&", "||", "|", "|&", "&", "\n", "\r\n"} {
		commands = append(commands, "gh pr view 12 "+op+" gh pr create", "gh pr create "+op+" gh pr view 12")
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			got, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": command})
			if !got {
				t.Fatalf("unverified command did not match: %q", command)
			}
			if strings.TrimSpace(reason) == "" {
				t.Fatal("matched command has no reason")
			}
		})
	}
}

func TestCommandClassifyFailsClosedForInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config domain.CommandClassify
		fields map[string]interface{}
	}{
		{"missing", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, nil},
		{"null", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, map[string]interface{}{"parameters.command": nil}},
		{"number", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, map[string]interface{}{"parameters.command": 12}},
		{"argv", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, map[string]interface{}{"parameters.command": []string{"gh", "pr", "view", "12"}}},
		{"empty", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, map[string]interface{}{"parameters.command": ""}},
		{"whitespace", domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}, map[string]interface{}{"parameters.command": " \n\t"}},
		{"empty field", domain.CommandClassify{Profile: "gh_read"}, map[string]interface{}{"parameters.command": "gh pr view 12"}},
		{"blank field", domain.CommandClassify{Field: " ", Profile: "gh_read"}, map[string]interface{}{"parameters.command": "gh pr view 12"}},
		{"empty profile", domain.CommandClassify{Field: "parameters.command"}, map[string]interface{}{"parameters.command": "gh pr view 12"}},
		{"unknown profile", domain.CommandClassify{Field: "parameters.command", Profile: "unknown"}, map[string]interface{}{"parameters.command": "gh pr view 12"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := EvalConditionWithDetail(domain.Condition{CommandClassify: &tc.config}, tc.fields)
			if !got || strings.TrimSpace(reason) == "" {
				t.Fatalf("got match=%v reason=%q, want match with reason", got, reason)
			}
		})
	}
}

func TestCommandClassifyValidation(t *testing.T) {
	valid := commandReadCondition()
	for _, tc := range []struct {
		name      string
		condition domain.Condition
		wantError bool
	}{
		{"valid", valid, false},
		{"and", domain.Condition{And: []domain.Condition{valid}}, false},
		{"or", domain.Condition{Or: []domain.Condition{valid}}, false},
		{"empty field", domain.Condition{CommandClassify: &domain.CommandClassify{Profile: "gh_read"}}, true},
		{"blank field", domain.Condition{CommandClassify: &domain.CommandClassify{Field: " ", Profile: "gh_read"}}, true},
		{"empty profile", domain.Condition{CommandClassify: &domain.CommandClassify{Field: "parameters.command"}}, true},
		{"unknown profile", domain.Condition{CommandClassify: &domain.CommandClassify{Field: "parameters.command", Profile: "unknown"}}, true},
		{"mixed leaf", domain.Condition{CommandClassify: valid.CommandClassify, Field: "tool_name", Operator: domain.OpEq, Value: "run"}, true},
		{"mixed and", domain.Condition{CommandClassify: valid.CommandClassify, And: []domain.Condition{valid}}, true},
		{"mixed classifiers", domain.Condition{CommandClassify: valid.CommandClassify, ShellClassify: &domain.ShellClassify{Field: "parameters.argv"}}, true},
		{"direct not", domain.Condition{Not: &valid}, true},
		{"nested not and", domain.Condition{Not: &domain.Condition{And: []domain.Condition{valid}}}, true},
		{"nested not or", domain.Condition{Not: &domain.Condition{Or: []domain.Condition{valid}}}, true},
		{"double not", domain.Condition{Not: &domain.Condition{Not: &valid}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCondition(&tc.condition, "test", 0, false)
			if (err != nil) != tc.wantError {
				t.Fatalf("validation error=%v, want error=%v", err, tc.wantError)
			}
		})
	}
}

func TestCommandClassifySegmentLearningExamples(t *testing.T) {
	for _, tc := range []struct {
		command string
		matches []bool
	}{
		{"gh pr view 12", []bool{false}},
		{"gh pr --repo o/r view 12", []bool{false}},
		{"gh pr view 12 && gh pr create", []bool{false, true}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			segments := classifyCommandSegments(tc.command)
			t.Logf("classifyCommandSegments(%q) = %+v", tc.command, segments)
			if len(segments) != len(tc.matches) {
				t.Fatalf("got %d segments, want %d", len(segments), len(tc.matches))
			}
			for i, segment := range segments {
				if segment.Match != tc.matches[i] {
					t.Errorf("segment %d: got match=%v, want %v", i, segment.Match, tc.matches[i])
				}
				if segment.Command == "" || segment.Reason == "" {
					t.Errorf("segment %d lacks command or reason: %+v", i, segment)
				}
			}
		})
	}
}

func TestCommandClassifyEvaluatorEscalation(t *testing.T) {
	policy := makePolicy([]domain.Rule{{RuleID: "gh-read", Conditions: commandReadCondition(), Effect: domain.EffectEscalate}})
	policy.OrgID = ""
	policy.Scope = domain.PolicyScope{ToolNames: []string{"bash"}}
	for _, tc := range []struct {
		command  string
		decision domain.Decision
	}{
		{"gh pr view 12", domain.DecisionAllowed},
		{"gh pr view 12 && gh pr merge 12", domain.DecisionEscalated},
		{"gh pr --repo X create", domain.DecisionEscalated},
		{"gh api repos/o/r/pulls -iXPATCH", domain.DecisionEscalated},
		{"gh unknown", domain.DecisionEscalated},
	} {
		t.Run(tc.command, func(t *testing.T) {
			result := NewEvaluator().Evaluate(envCmd("bash", tc.command), []domain.Policy{policy}, domain.PolicyModeEnforcement)
			if result.Decision != tc.decision {
				t.Fatalf("decision=%s, want %s", result.Decision, tc.decision)
			}
		})
	}
}

func TestCommandClassifyOtherCommandMentions(t *testing.T) {
	for _, tc := range []struct {
		command string
		match   bool
	}{
		{"jq .title", false}, {"ls -la", false}, {"git status", false}, {"echo ghost", false},
		{"echo agh", false}, {"echo gh1", false}, {"echo 1gh", false},
		{"echo _gh", false}, {"echo gh_", false}, {"echo .gh", false}, {"echo gh.", false},
		{"echo -gh", false}, {"echo gh-", false}, {"echo GH", false},
		{"echo gh", true}, {"echo 'gh'", true}, {"echo /gh/", true},
		{"cat ~/.config/gh/hosts.yml", true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			segments := classifyCommandSegments(tc.command)
			if len(segments) != 1 || segments[0].Match != tc.match {
				t.Fatalf("segments=%+v, want one segment with match=%v", segments, tc.match)
			}
			if tc.match && segments[0].Reason != "gh appears inside another command" {
				t.Fatalf("unexpected reason: %q", segments[0].Reason)
			}
		})
	}
}
