package engine_test

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

func argvFields(argv ...string) map[string]interface{} {
	out := make([]interface{}, len(argv))
	for i, s := range argv {
		out[i] = s
	}
	return map[string]interface{}{
		"tool_name":       "os_exec",
		"parameters.argv": out,
	}
}

// Argv0Allowlist enforces the allowed program list. argv[0] outside the
// list fires the rule. Allowed programs go through.
func TestEvalShellClassify_Argv0Allowlist(t *testing.T) {
	cond := domain.Condition{
		ShellClassify: &domain.ShellClassify{
			Field: "parameters.argv",
			Require: domain.ShellRequire{
				Argv0Allowlist: []string{"ls", "df", "uptime", "whoami", "date"},
				MaxArgc:        5,
			},
		},
	}
	cases := map[string]struct {
		argv []string
		want bool // true = rule fires (deny)
	}{
		"bare uptime":       {[]string{"uptime"}, false},
		"ls -la /tmp":       {[]string{"ls", "-la", "/tmp"}, false},
		"df -h":             {[]string{"df", "-h"}, false},
		"absolute path ls":  {[]string{"/usr/bin/ls", "-la"}, false}, // basename matches
		"rm (not allowed)":  {[]string{"rm", "-rf", "/"}, true},
		"sh -c (no shells)": {[]string{"sh", "-c", "ls"}, true},
		"empty argv":        {[]string{}, true},
		"argc cap exceeded": {[]string{"ls", "a", "b", "c", "d", "e", "f"}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fields := argvFields(c.argv...)
			if got := engine.EvalCondition(cond, fields); got != c.want {
				t.Errorf("argv=%v: got fire=%v want fire=%v", c.argv, got, c.want)
			}
		})
	}
}

// ArgvDenyPatterns reject specific metacharacters/flags.
func TestEvalShellClassify_DenyPatterns(t *testing.T) {
	cond := domain.Condition{
		ShellClassify: &domain.ShellClassify{
			Field: "parameters.argv",
			Require: domain.ShellRequire{
				Argv0Allowlist: []string{"ls", "find", "df"},
				ArgvDenyPatterns: []string{
					`[;&|` + "`" + `$]`,    // shell metacharacters
					`^-exec$`,              // find -exec → arbitrary execution
					`^--no-preserve-root$`, // rm bypass (defensive even if rm isn't allowed)
				},
			},
		},
	}
	deny := map[string][]string{
		"backtick in arg":    {"ls", "`whoami`"},
		"dollar sign":        {"ls", "$HOME"},
		"semicolon":          {"ls", ";rm -rf /"},
		"pipe":               {"ls", "|", "tee"},
		"find -exec":         {"find", ".", "-exec", "rm", "{}", ";"},
		"--no-preserve-root": {"ls", "--no-preserve-root"},
	}
	for name, argv := range deny {
		t.Run("deny/"+name, func(t *testing.T) {
			if !engine.EvalCondition(cond, argvFields(argv...)) {
				t.Errorf("did not fire on %v", argv)
			}
		})
	}
	allow := map[string][]string{
		"clean ls":   {"ls", "-la", "/tmp"},
		"clean find": {"find", ".", "-name", "*.go"},
		"clean df":   {"df", "-h"},
	}
	for name, argv := range allow {
		t.Run("allow/"+name, func(t *testing.T) {
			if engine.EvalCondition(cond, argvFields(argv...)) {
				t.Errorf("fired on %v", argv)
			}
		})
	}
}

// DeniedArgvPaths catches "ls /etc/shadow"-class attacks without
// blocking ls entirely.
func TestEvalShellClassify_DeniedArgvPaths(t *testing.T) {
	cond := domain.Condition{
		ShellClassify: &domain.ShellClassify{
			Field: "parameters.argv",
			Require: domain.ShellRequire{
				Argv0Allowlist: []string{"ls", "cat", "head", "tail"},
				DeniedArgvPaths: []string{
					"/etc/shadow",
					"/etc/passwd",
					"/proc/self/",
					"/root/",
					"/home/*/.ssh",
				},
			},
		},
	}
	deny := map[string][]string{
		"cat /etc/shadow":   {"cat", "/etc/shadow"},
		"head /etc/passwd":  {"head", "/etc/passwd"},
		"cat /etc//shadow":  {"cat", "/etc//shadow"},
		"cat /etc/./shadow": {"cat", "/etc/./shadow"},
		"ls ~/.ssh":         {"ls", "/home/alice/.ssh"},
	}
	for name, argv := range deny {
		t.Run("deny/"+name, func(t *testing.T) {
			if !engine.EvalCondition(cond, argvFields(argv...)) {
				t.Errorf("did not fire on %v", argv)
			}
		})
	}
	allow := map[string][]string{
		"ls /tmp":              {"ls", "/tmp"},
		"cat /var/log/app.log": {"cat", "/var/log/app.log"},
		"ls -la":               {"ls", "-la"},
	}
	for name, argv := range allow {
		t.Run("allow/"+name, func(t *testing.T) {
			if engine.EvalCondition(cond, argvFields(argv...)) {
				t.Errorf("fired on %v", argv)
			}
		})
	}
}

// FailClosed: argv field missing, wrong type, or single-string form
// (which is the dangerous "shell command" shape we explicitly refuse).
func TestEvalShellClassify_FailsClosed(t *testing.T) {
	cond := domain.Condition{
		ShellClassify: &domain.ShellClassify{
			Field:   "parameters.argv",
			Require: domain.ShellRequire{Argv0Allowlist: []string{"ls"}},
		},
	}
	cases := map[string]interface{}{
		"missing field":           nil, // sentinel
		"single string (no argv)": "ls -la /tmp",
		"argv contains object":    []interface{}{"ls", map[string]any{"injected": true}},
		"argv contains number":    []interface{}{"ls", 42},
		"empty array":             []interface{}{},
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			fields := map[string]interface{}{"tool_name": "os_exec"}
			if val != nil {
				fields["parameters.argv"] = val
			}
			if !engine.EvalCondition(cond, fields) {
				t.Errorf("did not fail-closed on %s", name)
			}
		})
	}
}

// Composes inside the And tree.
func TestEvalShellClassify_ComposesWithAnd(t *testing.T) {
	cond := domain.Condition{
		And: []domain.Condition{
			{Field: "tool_name", Operator: domain.OpEq, Value: "os_exec"},
			{ShellClassify: &domain.ShellClassify{
				Field: "parameters.argv",
				Require: domain.ShellRequire{
					Argv0Allowlist:  []string{"ls"},
					DeniedArgvPaths: []string{"/etc/shadow"},
				},
			}},
		},
	}
	// os_exec + ls /tmp → no fire
	if engine.EvalCondition(cond, argvFields("ls", "/tmp")) {
		t.Errorf("fired on legitimate ls /tmp")
	}
	// os_exec + ls /etc/shadow → fire
	if !engine.EvalCondition(cond, argvFields("ls", "/etc/shadow")) {
		t.Errorf("did not fire on ls /etc/shadow")
	}
	// wrong tool → no fire (AND short-circuits)
	wrong := map[string]interface{}{
		"tool_name":       "query",
		"parameters.argv": []interface{}{"ls", "/etc/shadow"},
	}
	if engine.EvalCondition(cond, wrong) {
		t.Errorf("fired on wrong tool (AND should short-circuit)")
	}
}
