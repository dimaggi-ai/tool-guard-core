package engine_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// productionShell mirrors a hardened operator policy. Allowlist is
// generous; denylist is paranoid; denied_argv_paths covers the
// sensitive-path set. This is what the demo should ship.
func productionShell() domain.Condition {
	return domain.Condition{
		ShellClassify: &domain.ShellClassify{
			Field: "parameters.argv",
			Require: domain.ShellRequire{
				Argv0Allowlist: []string{
					"uptime", "date", "whoami", "pwd", "hostname", "df",
					"ls", "cat", "head", "tail", "wc", "stat", "file",
				},
				DeniedArgvPaths: []string{
					"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/gshadow",
					"/etc/group", "/etc/krb5.keytab",
					"/etc/ssh/", "/etc/ssl/private/", "/etc/pki/tls/private/",
					"/root/", "/proc/self/", "/proc/**/environ",
					"/proc/**/maps", "/proc/**/mem", "/proc/**/cmdline",
					"/proc/**/fd/",
					"/var/lib/postgres", "/var/lib/mysql", "/var/lib/secrets",
					"/run/secrets/", "/var/run/secrets/", "/etc/kubernetes/",
					"/etc/postgresql/", "/etc/mysql/", "/etc/cron.d/",
					"/var/spool/cron/", "/var/log/auth.log", "/var/log/secure",
					"/var/log/audit/",
					"/home/*/.ssh", "/home/*/.aws", "/home/*/.gnupg",
					"/home/*/.docker", "/home/*/.netrc", "/home/*/.pgpass",
					"/home/*/.kube", "/home/*/.bash_history",
					"/home/*/.zsh_history", "/home/*/.psql_history",
					"/home/*/.mysql_history", "/home/*/.rediscli_history",
					"/home/*/.gitconfig", "/home/*/.git-credentials",
					"/home/*/.npmrc", "/home/*/.pypirc",
					"/home/*/.cargo/credentials",
					"/dev/mem", "/dev/kmem", "/dev/kcore", "/dev/port",
					"/sys/firmware/", "/sys/kernel/",
				},
				ArgvDenyPatterns: []string{
					`[;&|` + "`" + `$]`, // shell metas
					`\$\(`,              // command substitution
					`\${`,               // variable expansion
					`^-exec$`,           // find -exec
					`^--no-preserve-root$`,
					`^-c$`,    // sh/bash/python -c (interpreter eval)
					`^-eval$`, // perl -eval, ruby -eval
				},
				MaxArgc: 12,
			},
		},
	}
}

func argvF(argv ...string) map[string]interface{} {
	out := make([]interface{}, len(argv))
	for i, s := range argv {
		out[i] = s
	}
	return map[string]interface{}{
		"tool_name":       "os_exec",
		"parameters.argv": out,
	}
}

// Interpreters that can `-c` arbitrary code — denied via both argv0
// allowlist and the -c pattern.
func TestShell_Breakage_InterpreterEval(t *testing.T) {
	cond := productionShell()
	deny := map[string][]string{
		"sh -c":      {"sh", "-c", "ls"},
		"bash -c":    {"bash", "-c", "id"},
		"python -c":  {"python", "-c", "import os; os.system('id')"},
		"python3 -c": {"python3", "-c", "import os; os.system('id')"},
		"perl -e":    {"perl", "-e", "system('id')"},
		"perl -eval": {"perl", "-eval", "system('id')"},
		"ruby -e":    {"ruby", "-e", "exec('id')"},
		"node -e":    {"node", "-e", "require('child_process').execSync('id')"},
		"php -r":     {"php", "-r", "echo shell_exec('id');"},
		"awk system": {"awk", "BEGIN{system(\"id\")}"},
		"env evil":   {"env", "FOO=bar", "id"},
		"xargs cat":  {"xargs", "cat"},
		"sed e":      {"sed", "1e id"}, // sed -e with execute
	}
	for name, argv := range deny {
		t.Run(name, func(t *testing.T) {
			if !engine.EvalCondition(cond, argvF(argv...)) {
				t.Errorf("BYPASS: interpreter %v not denied", argv)
			}
		})
	}
}

// find / xargs tricks — find isn't in the allowlist by default so
// these all deny on Argv0, but if an operator adds find, the
// -exec / -newer / -delete patterns must still deny.
func TestShell_Breakage_FindTricks(t *testing.T) {
	cond := productionShell()
	deny := map[string][]string{
		"find -exec":         {"find", ".", "-exec", "rm", "{}", ";"},
		"find -delete":       {"find", ".", "-name", "*.tmp", "-delete"},
		"find -newer secret": {"find", ".", "-newer", "/etc/shadow"},
		"xargs -I":           {"xargs", "-I", "{}", "cat", "{}"},
	}
	for name, argv := range deny {
		t.Run(name, func(t *testing.T) {
			if !engine.EvalCondition(cond, argvF(argv...)) {
				t.Errorf("BYPASS: %v not denied", argv)
			}
		})
	}
}

// argv[0] absolute paths still resolve to basename. /usr/bin/sh is
// still "sh" — must be denied.
func TestShell_Breakage_Argv0AbsolutePath(t *testing.T) {
	cond := productionShell()
	deny := map[string][]string{
		"/usr/bin/sh -c":     {"/usr/bin/sh", "-c", "id"},
		"/bin/bash -c":       {"/bin/bash", "-c", "id"},
		"/usr/bin/python -c": {"/usr/bin/python", "-c", "import os"},
	}
	for name, argv := range deny {
		t.Run(name, func(t *testing.T) {
			if !engine.EvalCondition(cond, argvF(argv...)) {
				t.Errorf("BYPASS: absolute-path interpreter %v not denied", argv)
			}
		})
	}
}

// Paths inside argv pointing at credentials — denied_argv_paths must
// catch them after Clean(), including /etc//shadow normalisation.
func TestShell_Breakage_PathArgs(t *testing.T) {
	cond := productionShell()
	deny := map[string][]string{
		"cat /etc/shadow":               {"cat", "/etc/shadow"},
		"cat /etc//shadow":              {"cat", "/etc//shadow"},
		"cat /etc/./shadow":             {"cat", "/etc/./shadow"},
		"cat /etc/../etc/shadow":        {"cat", "/etc/../etc/shadow"},
		"head /etc/passwd":              {"head", "/etc/passwd"},
		"tail /var/log/auth.log":        {"tail", "/var/log/auth.log"},
		"cat /proc/1/environ":           {"cat", "/proc/1/environ"},
		"cat /proc/1/maps":              {"cat", "/proc/1/maps"},
		"cat /home/alice/.bash_history": {"cat", "/home/alice/.bash_history"},
		"cat /home/alice/.psql_history": {"cat", "/home/alice/.psql_history"},
		"cat ~/.ssh/id_rsa":             {"cat", "/home/alice/.ssh/id_rsa"},
		"cat .gitconfig":                {"cat", "/home/alice/.gitconfig"},
		"cat dockerenv":                 {"cat", "/.dockerenv"}, // not in deny list; documents the gap
		"cat /etc/ssh host key":         {"cat", "/etc/ssh/ssh_host_rsa_key"},
		"cat /etc/ssl private":          {"cat", "/etc/ssl/private/server.key"},
		"cat /run/secrets":              {"cat", "/run/secrets/kubernetes.io/serviceaccount/token"},
		"cat /etc/krb5.keytab":          {"cat", "/etc/krb5.keytab"},
		"cat /etc/postgresql cfg":       {"cat", "/etc/postgresql/16/main/pg_hba.conf"},
	}
	for name, argv := range deny {
		t.Run(name, func(t *testing.T) {
			fired := engine.EvalCondition(cond, argvF(argv...))
			if name == "cat dockerenv" && !fired {
				t.Logf("note: /.dockerenv not in deny list; documents the coverage gap")
				return
			}
			if !fired {
				t.Errorf("BYPASS: %v not denied", argv)
			}
		})
	}
}

// Legitimate commands — must still pass.
func TestShell_Breakage_LegitimateCommands(t *testing.T) {
	cond := productionShell()
	allow := map[string][]string{
		"uptime":             {"uptime"},
		"date":               {"date"},
		"whoami":             {"whoami"},
		"ls -la":             {"ls", "-la"},
		"ls /tmp":            {"ls", "/tmp"},
		"cat /var/log/myapp": {"cat", "/var/log/myapp.log"},
		"head -20 /tmp/x":    {"head", "-20", "/tmp/data.csv"},
		"tail -f /tmp/x":     {"tail", "-f", "/tmp/run.log"},
		"wc -l /tmp/x":       {"wc", "-l", "/tmp/data.csv"},
		"stat /tmp/x":        {"stat", "/tmp/file"},
		"file /tmp/x":        {"file", "/tmp/x"},
		"df -h":              {"df", "-h"},
		"hostname":           {"hostname"},
	}
	for name, argv := range allow {
		t.Run(name, func(t *testing.T) {
			if engine.EvalCondition(cond, argvF(argv...)) {
				t.Errorf("OVERBLOCK: legitimate %v denied", argv)
			}
		})
	}
}

// MaxArgc and other limits.
func TestShell_Breakage_LimitsAndEdge(t *testing.T) {
	cond := productionShell()
	// 12-arg cap; 13 args denied.
	longArgs := []string{"ls"}
	for i := 0; i < 12; i++ {
		longArgs = append(longArgs, "x")
	}
	if !engine.EvalCondition(cond, argvF(longArgs...)) {
		t.Errorf("MaxArgc=12 not enforced; argv length %d allowed", len(longArgs))
	}
	// Empty argv → fail closed (already covered)
	if !engine.EvalCondition(cond, argvF()) {
		t.Errorf("empty argv allowed")
	}
	// argv[0] empty string
	if !engine.EvalCondition(cond, argvF("", "ls")) {
		t.Errorf("empty argv[0] allowed")
	}
	// Embedded shell metas in args
	denyMeta := [][]string{
		{"ls", "$(id)"},
		{"ls", "`id`"},
		{"ls", "hello;id"},
		{"ls", "a|b"},
		{"ls", "a&b"},
		{"ls", "a${HOME}"},
	}
	for _, argv := range denyMeta {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if !engine.EvalCondition(cond, argvF(argv...)) {
				t.Errorf("BYPASS: shell-meta in arg %v not denied", argv)
			}
		})
	}
}

// Single-string body in parameters.argv — must be rejected.
func TestShell_Breakage_RejectStringCmd(t *testing.T) {
	cond := productionShell()
	// argv is a string, not an array
	fields := map[string]interface{}{
		"tool_name":       "os_exec",
		"parameters.argv": "ls -la /tmp",
	}
	if !engine.EvalCondition(cond, fields) {
		t.Errorf("string parameters.argv accepted (must be array)")
	}
}
