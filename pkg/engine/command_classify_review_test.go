package engine

// Added by the independent review of PR 64 (task 75). Each command below is escalated by the delivered classifier,
// and none of the engine or hook tests at 2960fc4 fails when the guard that escalates it is removed. The controls
// are the supported forms that sit next to those guards.

import "testing"

func TestReviewGuardsEscalate(t *testing.T) {
	groups := []struct {
		name     string
		commands []string
	}{
		{"an unquoted $ inside a free-text value or a repository selector", []string{
			"gh release view a$b",
			"gh pr list -R dimaggi-ai$@/tool-guard-core",
			"gh issue status --json=title=$ENV & pwd -P",
		}},
		{"a brace or a closing brace in an argument, quoted or not", []string{
			"gh issue list -a al{a,b}ice -A bob",
			"gh issue list --label='goo{1..3}d first issue'",
			"gh release list -L{",
			"gh repo view owner/reo --json nam{",
			"gh pr list --search 'draft:fals}e'",
			"gh issue list -a alice -A}bob",
		}},
		{"a command substitution or backtick inside quotes", []string{
			"gh pr list --search '$(id)'",
			"gh pr list --search 'd$(id)raft:false'",
			"gh pr list --search 'draft`id`:false'",
			"gh issue ls --assignee 'a`b'\ngh release view --repo o/r",
		}},
		{"a shell-special character inside quotes in an ls segment", []string{
			"ls 'a $0b'",
			"ls 'a`b'",
			"ls 'a`id` b'",
			"ls '(a b'",
			"ls 'a b('",
			"ls -- d--ocs{",
			"ls -laa{",
			"ls -{la",
			"ls -- do}c docss",
			"ls src d}cs",
			"ls \"< b\";gh pr view --help",
			"ls \"-<<<x-\"docs; ls src docs",
			"ls \"a>>f b\"",
			"ls '2>fa b'",
			"ls \"a|| b\"",
			"ls \"a b|\"",
			"ls 'a ; lsb'",
			"ls '&& b'",
			"ls '& b'",
		}},
		{"an unquoted glob character ? [ ]", []string{
			"ls ?\"a b\"",
			"gh repo list dimaggi-ai --limit 1?0",
			"gh pr view 12 --json ?title | jq .title",
			"gh release view v1.2[3",
			"gh pr list -s closed -L[5",
			"gh pr view 12 --json title,]ody",
			"ls -l /t]mp",
		}},
		{"the wrong number of operands", []string{
			"gh pr view 1 2",
			"gh pr list 5",
			"gh pr status 1",
			"gh issue list 1",
			"gh issue status 1",
			"gh issue view",
			"gh release list env",
			"gh repo list '5' 'all'",
		}},
		{"a PR or issue operand that is not a number", []string{
			"gh pr view '!'",
			"gh pr view \\!",
			"gh pr view .",
			"gh pr diff \\*",
		}},
		{"an empty owner or repository in a selector", []string{
			"gh pr view 1 -R /r",
			"gh pr view 1 -R o/",
			"gh release view --repo /r",
		}},
		{"an option value that is empty or starts with a dash", []string{
			"gh pr view 1 --json=",
			"gh pr view 1 --json -",
			"gh pr list -L -1",
			"gh pr list --search \"\"",
			"gh pr list -L --hostname",
		}},
		{"a lone dash", []string{
			"gh pr view 12 - --json title | jq .title",
		}},
		{"a value attached to a boolean flag", []string{
			"gh pr view 1 --comments=false",
			"gh repo list --help=\"all\"",
		}},
		{"flags that pr checks does not support", []string{
			"gh pr checks 1 --watch",
			"gh pr checks 1 --fail-fast",
			"gh pr checks --rebase",
			"gh repo ls --required 1",
			"gh pr status --required ; gh issue list --label='good first issue'",
		}},
		{"flags that only pr diff supports, on other commands", []string{
			"gh pr ls --name-only && gh issue list --label='good first issue'",
			"gh pr diff 12 || gh pr list --name-only",
		}},
		{"list-only flags on other commands", []string{
			"gh release ls -a='title,body'",
			"gh release list -S='dimaggi-ai/tool-guard-core' -S='0'",
			"gh pr view \"12\" -S \"o/r\"",
		}},
		{"the comments flag on commands that do not support it", []string{
			"gh repo view -cc",
			"gh issue ls -cc",
			"gh pr checks -c \"5\"",
			"gh pr view 12 ;gh pr status --comments",
		}},
		{"the limit flag on commands that do not support it", []string{
			"gh repo view -L=\\=x ;gh pr diff 12 --name-only",
			"gh issue status -L='a>b'",
		}},
		{"--json on pr diff and a flag before a non-read command", []string{
			"gh pr diff 1 --json x",
			"gh --json=title pr list -ac=\\~",
		}},
		{"a control operator with no command before it", []string{
			"&& gh pr view 1",
			"&&gh release list",
			"||ls -lala",
			"gh release list&&&&gh pr list",
		}},
		{"a gh.exe mention", []string{
			"ls gh.exe",
		}},
		{"a gh mention glued to a quoted word in an ls segment", []string{
			"ls \"a b\"gh rGpo view",
		}},
		{"input that once made a shorter loop index past the end", []string{
			"<",
			">",
			"\\jq .\"title\\",
			"gh pr d\" 12\\",
		}},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			for _, command := range g.commands {
				if class, reason := ClassifyCommand(command); class != CommandUnverified {
					t.Errorf("ClassifyCommand(%q) = %s (%s), want unverified", command, class, reason)
				}
				fields := map[string]interface{}{"parameters.command": command}
				if got, _ := EvalConditionWithDetail(commandReadCondition(), fields); !got {
					t.Errorf("the gh_read condition did not match %q", command)
				}
			}
		})
	}
}

func TestReviewSupportedFormsNextToThoseGuards(t *testing.T) {
	controls := []struct {
		want     CommandClass
		commands []string
	}{
		{CommandVerifiedRead, []string{
			"gh pr view -c 12",
			"gh pr view 1 -cc",
			"gh pr checks 12 --required",
			"gh pr diff 12 --name-only",
			"gh pr list -s closed -L 5",
			"gh release view --repo o/r",
			"gh pr view 12 --json title | jq .title",
			"gh issue view 75 --comments --json body",
			"gh pr list --search \"is:open review:required\"",
			"gh pr list --state open --limit 20",
			"gh pr list --author alice --label bug",
			"gh issue list -a alice -A bob",
			"gh issue list --label bug",
			"gh pr diff 12 --patch",
			"gh pr diff 12 --color never",
			"gh pr view --help",
			"gh pr list -s closed -L 5",
			"gh pr list --repo=dimaggi-ai/tool-guard-core --json number,title",
		}},
		{CommandProvenUnrelated, []string{
			"ls -la",
			"pwd -P",
			"ls src docs",
		}},
	}
	for _, c := range controls {
		for _, command := range c.commands {
			if class, reason := ClassifyCommand(command); class != c.want {
				t.Errorf("ClassifyCommand(%q) = %s (%s), want %s", command, class, reason, c.want)
			}
		}
	}
}
