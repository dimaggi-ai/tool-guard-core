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
		"jq .title", "jq '.title'", `jq ".title"`, `jq .ti\tle`,
		`gh pr view '#1'`, `gh pr view \#1`, `gh pr view x#1`, `gh pr view "#1"`,
		"gh pr view 1\ngh issue view 2",
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
		"gh --hostname example.test api repos/o/r/pulls",
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
		"gh api user/repos --jq .\r -X POST -f name=evil",
		"gh pr view #'\ngh pr merge 1 --admin #'",
		"gh pr view --repo # '\ngh pr merge 1 # '",
		"GH pr merge 1", "Gh pr merge 1", "gh.exe pr merge 1",
		`find . -exec g\h pr merge 1 \;`,
		`find . -exec "g"h pr merge 1 \;`,
		`find . -exec g''h pr merge 1 \;`,
		`find . -exec g$'\x68' pr merge 1 \;`,
		`stdbuf -o0 g\h pr merge 1`,
		`setsid g""h pr merge 12`,
		`ssh host 'g""h pr merge 1'`,
		`find . -exec $P pr merge 1 \;`,
		"\r", "gh pr view 1 # comment",
		// Further runtime expansion and executable-suffix cases found in review.
		"fc -s",
		`find . -exec g[h] pr merge 1 \;`,
		`find . -exec gh.exe pr merge 1 \;`,
		`ssh host 'GH.EXE pr merge 1'`,
		"ssh host 'g\\\nh pr merge 1'",
		"gh pr view \\\n#'\ngh pr merge 1 #'",

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
		{"ls -la", domain.DecisionEscalated},
		{"git status", domain.DecisionEscalated},
		{"python3 --version", domain.DecisionEscalated},
		{"gh pr view \\\n12", domain.DecisionEscalated},
		{"gh pr view 12 2>/dev/null", domain.DecisionEscalated},
		{"jq .title", domain.DecisionAllowed},
		{"gh pr view 1 |& jq .title", domain.DecisionEscalated},
		{"jq .title |& gh issue view 2", domain.DecisionEscalated},
		{"jq .title |& jq .title", domain.DecisionEscalated},
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
		reason  string
	}{
		{"jq .title", false, "verified jq .title helper"}, {"ls -la", true, "unsupported command form"}, {"git status", true, "unsupported command form"}, {"echo ghost", true, "unsupported command form"},
		{"echo agh", true, "unsupported command form"}, {"echo gh1", true, "unsupported command form"}, {"echo 1gh", true, "unsupported command form"},
		{"echo _gh", true, "unsupported command form"}, {"echo gh_", true, "unsupported command form"}, {"echo .gh", true, "unsupported command form"}, {"echo gh.", true, "unsupported command form"},
		{"echo -gh", true, "unsupported command form"}, {"echo gh-", true, "unsupported command form"}, {"echo GH", true, "gh appears inside another command"},
		{"echo gh", true, "gh appears inside another command"}, {"echo 'gh'", true, "gh appears inside another command"}, {"echo /gh/", true, "gh appears inside another command"},
		{"cat ~/.config/gh/hosts.yml", true, "gh appears inside another command"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			segments := classifyCommandSegments(tc.command)
			if len(segments) != 1 || segments[0].Match != tc.match {
				t.Fatalf("segments=%+v, want one segment with match=%v", segments, tc.match)
			}
			if segments[0].Reason != tc.reason {
				t.Fatalf("unexpected reason: %q", segments[0].Reason)
			}
		})
	}
}

func TestCommandClassifyFailClosedReasons(t *testing.T) {
	for _, tc := range []struct{ command, reason string }{
		{"\r", "unsupported control character"},
		{"gh api repos/o/r/issues --repo o/r", "unknown gh option"},
		{"gh --repo o/r api repos/o/r/issues", "unknown gh option"},
		{"gh -Ro/r api repos/o/r/issues", "unknown gh option"},
		{"gh pr view 12 --hostname example.test", "unknown gh option"},
		{"gh --hostname example.test pr view 12", "unknown gh option"},
		{"gh repo view o/r -R o/r", "unknown gh option"},
		{"gh -Ro/r repo list", "unknown gh option"},
		{"gh pr view 1 |& jq .title", "stderr pipe redirection is not verified"},
		{"jq .title |& gh issue view 2", "stderr pipe redirection is not verified"},
		{"jq .title |& jq .title", "stderr pipe redirection is not verified"},
		{"fc -s", "wrapper or shell grammar is not verified"},
		{"gh pr view #'\ngh pr merge 1 #'", "shell comment is not verified"},
		{"#'\ngh pr merge 1", "shell comment is not verified"},
		{"echo ok;#'\ngh pr merge 1", "shell comment is not verified"},
		{"GH.EXE pr merge 1", "gh program name is not the exact literal gh"},
		{"'/usr/bin/gh' pr view 1", "gh program name is not the exact literal gh"},
		{`find . -exec g$'\x68' pr merge 1 \;`, "ANSI-C or locale quoting is not verified"},
		{`echo $"x"`, "ANSI-C or locale quoting is not verified"},
		{`find . -exec $P pr merge 1 \;`, "unresolved word in another command"},
		{`find . -exec g[h] pr merge 1 \;`, "unresolved word in another command"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": tc.command})
			if !got || reason != "command_classify: "+tc.reason {
				t.Fatalf("match=%v reason=%q, want %q", got, reason, tc.reason)
			}
		})
	}
	for c := byte(0); c <= 127; c++ {
		if c >= 32 && c != 127 || c == '\t' || c == '\n' {
			continue
		}
		for _, command := range []string{string(c), "gh pr view '" + string(c) + "'", "echo " + string(c)} {
			results := classifyCommandSegments(command)
			if len(results) != 1 || !results[0].Match || results[0].Reason != "unsupported control character" {
				t.Fatalf("control %d: %+v", c, results)
			}
		}
	}
}

func TestCommandClassifyLiteralHashes(t *testing.T) {
	for _, command := range []string{`echo '#text'`, `echo \#text`, `echo x#text`, `echo "#text"`, "echo x\\\n#text"} {
		want := "unsupported command form"
		if strings.Contains(command, "\\\n") {
			want = "line continuation is not verified"
		}
		if results := classifyCommandSegments(command); len(results) != 1 || !results[0].Match || results[0].Reason != want {
			t.Fatalf("literal hash %q: %+v", command, results)
		}
	}
}

func TestCommandClassifyAllowlistBoundaries(t *testing.T) {
	for _, tc := range []struct{ command, reason string }{
		{`ssh host 'g[h] pr merge 1'`, "unsupported command form"},
		{`python3 -c 'import os; os.system("g"+"h"+" pr merge 1")'`, "unsupported command form"},
		{`python3 -c 'import os; os.system("g" + "h pr merge 1")'`, "unsupported command form"},
		{`printf -v X '%s%s' g h; trap '$X pr merge 1' EXIT`, "unsupported command form"},
		{`printf 'g%s pr merge 1' h | busybox sh`, "unsupported command form"},
		{`./run.sh`, "unsupported command form"},
		{`jq -r .title`, "unsupported command form"},
		{`jq .`, "unsupported command form"},
		{`jq .title file`, "unsupported command form"},
		{`jq -f f`, "unsupported command form"},
		{`jq -L d .title`, "unsupported command form"},
		{`jq -L d`, "unsupported command form"},
		{`jq -- .title`, "unsupported command form"},
		{`JQ .title`, "unsupported command form"},
		{`"jq" .title`, "program name is not a bare literal"},
		{`j\q .title`, "program name is not a bare literal"},
		{`/usr/bin/jq .title`, "unsupported command form"},
		{`X=1 jq .title`, "assignment scope is unresolved"},
		{`jq .title >out`, "redirection in helper segment is not verified"},
		{`jq '$FILTER'`, "unsupported command form"},
		{`jq "$FILTER"`, "unresolved word in another command"},
		{`jq 'gh'`, "gh appears inside another command"},
		{`jq '.title`, "unresolved word in another command"},
		{`sort --compress-program=x`, "unsupported command form"},
		{`sort -o out`, "unsupported command form"},
		{`gh pr view "$[1+1]"`, "legacy arithmetic expansion is unresolved"},
		{`gh pr view '$[1+1]'`, "legacy arithmetic expansion is unresolved"},
		{`gh pr view $[1+1]`, "legacy arithmetic expansion is unresolved"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			match, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": tc.command})
			if !match || reason != "command_classify: "+tc.reason {
				t.Fatalf("match=%v reason=%q, want %q", match, reason, tc.reason)
			}
		})
	}
	for _, program := range []string{"trap", "mapfile", "readarray", "compgen", "complete", "bind", "ash", "mksh", "yash", "csh", "tcsh", "rbash", "busybox", "python3", "find", "ssh", "ls", "git", "echo"} {
		results := classifyCommandSegments(program)
		if len(results) != 1 || !results[0].Match || results[0].Reason != "unsupported command form" {
			t.Errorf("program %q: %+v", program, results)
		}
	}
	for _, operand := range []string{"1\\\n2", "\"1\\\n2\"", "'1\\\n2'", "$\\\nNUMBER", "\"$\\\nNUMBER\"", "$\\\n(gh pr merge 1)", "\"$\\\n(gh pr merge 1)\""} {
		results := classifyCommandSegments("gh pr view " + operand)
		if len(results) != 1 || !results[0].Match || results[0].Reason != "line continuation is not verified" {
			t.Errorf("continued operand %q: %+v", operand, results)
		}
	}
	for _, command := range []string{"gh pr view 1", "jq .title", "echo ok"} {
		for _, redirect := range []string{">out", ">>out", ">|out", "2>/dev/null", ">&2", ">&-", "<&0", "<&-", "<file", "<>file", "&>out", "&>>out", "<<EOF\ntext\nEOF", "<<-EOF\ntext\nEOF", "<<<text"} {
			match, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": command + " " + redirect})
			want := "command_classify: redirection in helper segment is not verified"
			if strings.HasPrefix(command, "gh ") {
				want = "command_classify: redirection in gh segment is not verified"
			}
			if strings.HasPrefix(redirect, "<<") {
				want = "command_classify: substitution, group or here-document is unresolved"
			}
			if !match || reason != want {
				t.Errorf("redirection %q %q: match=%v reason=%q, want %q", command, redirect, match, reason, want)
			}
		}
	}
}

func TestCommandClassifyEscalationOverridesAllow(t *testing.T) {
	policy := makePolicy([]domain.Rule{
		{RuleID: "allow", Conditions: domain.Condition{Field: "tool_name", Operator: domain.OpEq, Value: "bash"}, Effect: domain.EffectAllow},
		{RuleID: "read", Conditions: commandReadCondition(), Effect: domain.EffectEscalate},
	})
	policy.OrgID = ""
	policy.Scope = domain.PolicyScope{ToolNames: []string{"bash"}}
	for _, command := range []string{"ls -la", "git status", "python3 --version"} {
		result := NewEvaluator().Evaluate(envCmd("bash", command), []domain.Policy{policy}, domain.PolicyModeEnforcement)
		if result.Decision != domain.DecisionEscalated {
			t.Errorf("%q: decision=%s", command, result.Decision)
		}
	}
}

func TestCommandClassifyConstructedCommandsInCompounds(t *testing.T) {
	for _, payload := range []string{
		`ssh host 'g[h] pr merge 1'`,
		`python3 -c 'import os; os.system("g" + "h pr merge 1")'`,
		`trap '$X pr merge 1' EXIT`,
		`mapfile -C '$X pr merge 1' -c 1 a < /etc/hosts`,
		`readarray -C '$X pr merge 1' -c 1 a`,
		`compgen -C '$X pr merge 1'`,
		`complete -C '$X pr merge 1' x`,
		`bind -x '"x":$X pr merge 1'`,
		`./run.sh`, `jq .title ''`, `jq .title; g[h] pr merge 1`,
		"gh api $\\\nARGS", "gh api \"$\\\nARGS\"",
	} {
		for _, op := range []string{";", "&&", "||", "|", "|&", "&", "\n"} {
			for _, command := range []string{"gh pr view 1 " + op + " " + payload, payload + " " + op + " jq .title"} {
				if match, _ := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": command}); !match {
					t.Errorf("unverified compound accepted: %q", command)
				}
			}
		}
	}
}
