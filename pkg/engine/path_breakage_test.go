package engine_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// realisticDenied is the production-grade denied prefix list — the one
// every Tool Guard demo policy SHOULD ship with. The current demo
// `os-protect.yaml` is a strict subset; the breakage tests below
// surface every path that's sensitive but isn't yet covered there.
// Once we update the example policy, both the unit tests AND the
// live policy march in lockstep.
var realisticDenied = []string{
	// Classic credential files
	"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/gshadow", "/etc/group",
	// Cron / scheduler
	"/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
	"/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/",
	// PAM / security
	"/etc/security/", "/etc/pam.d/", "/etc/login.defs",
	// SSH server keys
	"/etc/ssh/", // covers /etc/ssh/ssh_host_*_key, sshd_config
	// TLS private keys
	"/etc/ssl/private/", "/etc/pki/tls/private/",
	// Kerberos
	"/etc/krb5.keytab", "/etc/krb5.conf",
	// DBs server-side
	"/etc/postgresql/", "/etc/mysql/", "/etc/redis/",
	// Container runtime / orchestrator
	"/etc/kubernetes/", "/etc/docker/", "/.dockerenv", "/run/.containerenv",
	"/run/secrets/", "/var/run/secrets/", "/var/lib/postgres", "/var/lib/mysql",
	"/var/lib/secrets",
	// System data
	"/root/",
	// /proc
	"/proc/self/", "/proc/[0-9]", // narrow form handled by ** below
	// /sys (kernel info)
	"/sys/firmware/", "/sys/kernel/",
	// /dev sensitive devices
	"/dev/mem", "/dev/kmem", "/dev/port", "/dev/kcore",
	// Per-user secret dirs and files
	"/home/*/.ssh", "/home/*/.aws", "/home/*/.gnupg", "/home/*/.docker",
	"/home/*/.netrc", "/home/*/.pgpass", "/home/*/.kube",
	"/home/*/.bash_history", "/home/*/.zsh_history",
	"/home/*/.psql_history", "/home/*/.mysql_history", "/home/*/.rediscli_history",
	"/home/*/.gitconfig", "/home/*/.git-credentials",
	"/home/*/.npmrc", "/home/*/.pypirc", "/home/*/.cargo/credentials",
	// Logs that contain authentications / sensitive info
	"/var/log/auth.log", "/var/log/secure", "/var/log/audit/",
	// Generic process directories deeper than /proc/<pid>/
	"/proc/**/environ", "/proc/**/maps", "/proc/**/mem", "/proc/**/cmdline",
	"/proc/**/root", "/proc/**/cwd", "/proc/**/fd/",
}

func realisticCond() domain.Condition {
	return domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst:              true,
				AbsoluteOnly:            true,
				ResolveSymlinks:         false, // don't depend on FS in unit test
				DenyShellMetas:          true,  // deny on suspicion when shell ops appear in the path string
				MaxPathLength:           4096,
				DeniedCanonicalPrefixes: realisticDenied,
			},
		},
	}
}

// Sensitive paths the demo policy currently misses but the realistic
// (production-grade) policy MUST cover.
func TestPath_Breakage_SensitivePaths(t *testing.T) {
	cond := realisticCond()
	mustDeny := []string{
		// Cron
		"/etc/crontab",
		"/etc/cron.d/important",
		"/var/spool/cron/crontabs/root",
		// SSH server keys
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/sshd_config",
		// TLS private keys
		"/etc/ssl/private/server.key",
		"/etc/pki/tls/private/wildcard.key",
		// Kerberos
		"/etc/krb5.keytab",
		// DB server configs
		"/etc/postgresql/16/main/pg_hba.conf",
		"/etc/mysql/mariadb.conf.d/50-server.cnf",
		// Container runtime
		"/.dockerenv",
		"/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/etc/docker/daemon.json",
		// /proc for non-self PIDs
		"/proc/1/environ",
		"/proc/12345/cmdline",
		"/proc/1/maps",
		"/proc/self/fd/0",
		"/proc/self/root/etc/passwd",
		// /sys
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61",
		// /dev sensitive
		"/dev/mem",
		"/dev/kmem",
		"/dev/kcore",
		// Per-user histories with creds/queries
		"/home/alice/.bash_history",
		"/home/bob/.psql_history",
		"/home/eve/.mysql_history",
		"/home/alice/.gitconfig",
		"/home/alice/.git-credentials",
		"/home/alice/.npmrc",
		"/home/alice/.pypirc",
		"/home/alice/.cargo/credentials",
		// Auth logs
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/audit/audit.log",
		// PAM
		"/etc/security/access.conf",
		"/etc/pam.d/sshd",
		// Other deny variants via normalization
		"/etc//crontab",       // double-slash normalized to /etc/crontab
		"/etc/./crontab",      // /. normalized
		"/etc/../etc/crontab", // /../ normalized
	}
	for _, p := range mustDeny {
		t.Run(p, func(t *testing.T) {
			if !engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("BYPASS: %q is sensitive but rule did NOT fire", p)
			}
		})
	}
}

// Paths that SHOULD remain allowed even under the production deny list.
// These exist to catch over-blocking regressions.
func TestPath_Breakage_LegitimatePaths(t *testing.T) {
	cond := realisticCond()
	mustAllow := []string{
		"/tmp/notes.txt",
		"/tmp/agent/scratch.json",
		"/var/log/myapp.log",
		"/srv/data/exports/q1.csv",
		"/usr/share/dict/words",
		"/opt/myapp/data/file.json",
		"/etc/hostname",  // generally not denied
		"/etc/timezone",  // generally not denied
		"/etc/lsb-release",
		"/proc/cpuinfo",   // generic /proc data (not a pid dir)
		"/proc/meminfo",
		"/proc/version",
		"/home/alice/Documents/notes.txt",
		"/home/alice/Downloads/song.mp3",
		"/var/log/myapp/run.log",
	}
	for _, p := range mustAllow {
		t.Run(p, func(t *testing.T) {
			if engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("OVERBLOCK: legitimate path %q fired the rule", p)
			}
		})
	}
}

// Operations embedded INSIDE a path string. The path is a single
// filesystem path argument — shell metacharacters in it are inert.
// But many of these shapes are also COMMAND injection vectors that
// shouldn't appear in a normal path. We accept them as-is when they
// don't map to a denied prefix (the FS open() will simply fail) — the
// risk surface is captured at the shell layer, not here. These
// tests document the boundary: path_classify does NOT pretend to
// understand command injection in path strings.
func TestPath_Breakage_OperationsInsidePath(t *testing.T) {
	cond := realisticCond()
	// Paths containing shell metacharacters — denied via DenyShellMetas
	// regardless of whether they'd map to a denied prefix. Defense in
	// depth: a legitimate agent has no reason to ask for a path like
	// /tmp/file;cat /etc/shadow.
	shellMetaPaths := []string{
		"/tmp/file;cat /etc/shadow",
		"/tmp/file && cat /etc/shadow",
		"/tmp/file | tee out.txt",
		"/tmp/$(whoami)",
		"/tmp/`whoami`",
		"/tmp/file\nrm -rf /",
		"/tmp/file\x00.txt",
	}
	for _, p := range shellMetaPaths {
		t.Run("shellmeta/"+strings.ReplaceAll(strings.ReplaceAll(p, "\n", `\n`), "\x00", `\0`), func(t *testing.T) {
			if !engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("BYPASS: shell-meta path %q not denied (DenyShellMetas should have fired)", p)
			}
		})
	}
	// Paths that contain a denied prefix but ALSO have shell ops after.
	// These MUST deny — the prefix match is enough.
	mustDeny := []string{
		"/etc/shadow;cat /tmp/x",
		"/etc/shadow && echo hi",
		"/etc/shadow|tee out.txt",
		"/etc/passwd\nappend",
		"/etc/passwd\x00.txt",
	}
	for _, p := range mustDeny {
		t.Run("deny/"+strings.ReplaceAll(p, "\n", `\n`), func(t *testing.T) {
			if !engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("BYPASS: %q starts with denied prefix but rule did NOT fire", p)
			}
		})
	}
}

// Unicode lookalike characters — homograph attacks. Cyrillic 'о' is a
// different codepoint from Latin 'o' but visually identical. The OS
// treats them as different filenames; the proxy must NOT be fooled
// into denying the Cyrillic form thinking it's the Latin one (or vice
// versa). This test documents the expected behaviour: cyrillic
// /etc/shadоw is a LITERAL different file (which the FS likely does
// not have) and is allowed.
func TestPath_Breakage_UnicodeLookalikes(t *testing.T) {
	cond := realisticCond()
	// Latin /etc/shadow → denied.
	if !engine.EvalCondition(cond, pathFields("/etc/shadow")) {
		t.Fatal("regression: Latin /etc/shadow not denied")
	}
	// Cyrillic 'о' in shadоw → literally different bytes, not in our
	// denied list, ALLOWED. Caller's FS will return ENOENT.
	cyrillic := "/etc/shadоw" // 'о' is U+043E
	if engine.EvalCondition(cond, pathFields(cyrillic)) {
		t.Logf("unexpected: cyrillic %q matched a denied prefix (perhaps Clean normalised?)", cyrillic)
	}
}

// Trailing whitespace / NUL — paths whose suffix differs from the
// canonical denied prefix.
func TestPath_Breakage_TrailingArtifacts(t *testing.T) {
	cond := realisticCond()
	// Trailing space is part of the filename on Linux.
	// /etc/shadow + space != /etc/shadow ; not in deny list.
	// However, the filesystem usually doesn't have such a file.
	// We accept this as ALLOWED — open() will return ENOENT.
	cases := map[string]bool{ // path → wantDeny
		"/etc/shadow":   true,
		"/etc/shadow ":  false, // trailing space — literal different filename
		"/etc/shadow\t": true,  // control byte → DenyShellMetas
		"/etc/shadow.":  false, // trailing dot — literal different filename on Linux
	}
	for p, wantDeny := range cases {
		t.Run(p, func(t *testing.T) {
			fired := engine.EvalCondition(cond, pathFields(p))
			if fired != wantDeny {
				t.Errorf("path %q: rule fired=%v, expected fire=%v", p, fired, wantDeny)
			}
		})
	}
}

// Empty / just-slash / very long.
func TestPath_Breakage_EdgeShapes(t *testing.T) {
	cond := realisticCond()
	// Empty path: absolute_only fires.
	if !engine.EvalCondition(cond, pathFields("")) {
		t.Errorf("empty path not denied")
	}
	// Just slash: matches no deny prefix.
	if engine.EvalCondition(cond, pathFields("/")) {
		t.Logf("note: '/' fired some rule (probably /etc/* prefix doesn't match)")
	}
	// Very long path (8KB component) — MaxPathLength=4096 denies.
	long := "/tmp/" + strings.Repeat("a", 8192)
	if !engine.EvalCondition(cond, pathFields(long)) {
		t.Errorf("very long path not denied; max_path_length should have fired")
	}
	// Reasonable-length path inside /tmp — allowed.
	reasonable := "/tmp/" + strings.Repeat("a", 100)
	if engine.EvalCondition(cond, pathFields(reasonable)) {
		t.Errorf("reasonable /tmp path denied; expected allow")
	}
}
