package engine_test

import (
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

func TestEvalPathClassify_RelativePolicyPathIsPortable(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.file_path",
			Require: domain.PathRequire{
				CleanFirst:              true,
				DeniedCanonicalPrefixes: []string{"policies/"},
			},
		},
	}
	for _, candidate := range []string{
		"policies/custom.yaml",
		filepath.Join("policies", "custom.yaml"),
	} {
		fields := map[string]interface{}{"parameters.file_path": candidate}
		if !engine.EvalCondition(cond, fields) {
			t.Errorf("portable relative policy path %q did not fire deny rule", candidate)
		}
	}
}

func pathFields(p string) map[string]interface{} {
	return map[string]interface{}{
		"tool_name":       "os_read_file",
		"parameters.path": p,
	}
}

// Canonical: every empirically-confirmed bypass from earlier this
// session must now fire the rule. This is the regression for the
// "regex didn't handle path normalization" finding.
func TestEvalPathClassify_ClosesConfirmedBypasses(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				AbsoluteOnly: true,
				CleanFirst:   true,
				DeniedCanonicalPrefixes: []string{
					"/etc/shadow",
					"/etc/passwd",
					"/etc/sudoers",
					"/etc/gshadow",
					"/etc/group",
					"/root/",
					"/proc/self/",
					"/var/lib/postgres/",
					"/var/lib/mysql/",
					"/home/*/.ssh",
					"/home/*/.aws",
					"/home/*/.gnupg",
					"/home/*/.docker",
					"/home/*/.netrc",
					"/home/*/.pgpass",
					"/home/*/.kube",
				},
			},
		},
	}

	must := map[string]string{
		"canonical /etc/shadow":        "/etc/shadow",
		"canonical /etc/passwd":        "/etc/passwd",
		"/etc//shadow double slash":    "/etc//shadow",
		"/etc/./shadow dot":            "/etc/./shadow",
		"//etc//shadow multi-slash":    "//etc//shadow",
		"/etc/../etc/shadow loopback":  "/etc/../etc/shadow",
		"/etc/foo/../shadow traversal": "/etc/foo/../shadow",
		"/proc/self/environ":           "/proc/self/environ",
		"/proc/self/maps":              "/proc/self/maps",
		"/etc/group":                   "/etc/group",
		"~/.docker masked":             "/home/alice/.docker/config.json",
		"~/.netrc":                     "/home/alice/.netrc",
		"~/.pgpass":                    "/home/alice/.pgpass",
		"~/.kube/config":               "/home/alice/.kube/config",
		"~/.ssh/id_rsa":                "/home/alice/.ssh/id_rsa",
		"/root/anything":               "/root/.bash_history",
		"relative path":                "etc/passwd",
		"empty string":                 "",
	}
	for name, path := range must {
		t.Run("deny/"+name, func(t *testing.T) {
			if !engine.EvalCondition(cond, pathFields(path)) {
				t.Errorf("rule did NOT fire on %q; expected deny", path)
			}
		})
	}

	mustAllow := map[string]string{
		"/tmp/foo":           "/tmp/foo",
		"/var/log/myapp.log": "/var/log/myapp.log",
		"/srv/data/file.csv": "/srv/data/file.csv",
	}
	for name, path := range mustAllow {
		t.Run("allow/"+name, func(t *testing.T) {
			if engine.EvalCondition(cond, pathFields(path)) {
				t.Errorf("rule fired on %q; expected allow", path)
			}
		})
	}
}

// TestEvalPathClassify_UNCPrefixMatchesForwardSlashCandidate pins that a
// UNC-style deny prefix matches a UNC-style candidate path regardless of
// which slash form each one is written in. Found by an independent
// adversarial review ahead of the v0.5.2 release: path.Clean (used above
// to correctly collapse a plain double-slash typo like "//etc//shadow"
// down to "/etc/shadow" - see TestEvalPathClassify_ClosesConfirmedBypasses)
// ALSO collapses a genuine UNC-notation candidate written with forward
// slashes ("//server/share/...", the form agent tool-call text always
// uses - see evalPathClassify's posixAbs comment) down to a single
// leading slash. matchPathPrefix's normalizeIfWindowsPath only swaps "\"
// for "/" on an operator-authored native prefix ("\\server\share\...");
// it never collapses redundant slashes. Without also collapsing the
// prefix the same way, the two sides permanently disagree on slash count
// and a UNC-style protected path never matches - silently disabling path
// protection for any network-share target, on any platform, regardless
// of which slash form the operator used to author the prefix.
func TestEvalPathClassify_UNCPrefixMatchesForwardSlashCandidate(t *testing.T) {
	nativePrefix := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst:              true,
				DeniedCanonicalPrefixes: []string{`\\server\share\protected`},
			},
		},
	}
	if !engine.EvalCondition(nativePrefix, pathFields("//server/share/protected/file.txt")) {
		t.Error("forward-slash UNC candidate did not match a native-backslash-authored UNC deny prefix; expected deny")
	}

	forwardSlashPrefix := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst:              true,
				DeniedCanonicalPrefixes: []string{"//server/share/protected"},
			},
		},
	}
	if !engine.EvalCondition(forwardSlashPrefix, pathFields("//server/share/protected/file.txt")) {
		t.Error("forward-slash UNC candidate did not match a forward-slash-authored UNC deny prefix; expected deny")
	}

	// A different share must not match either prefix form — the fix must
	// not become overly permissive while closing the mismatch above.
	if engine.EvalCondition(nativePrefix, pathFields("//server/other-share/file.txt")) {
		t.Error("unrelated share matched the \\\\server\\share\\protected deny prefix; expected allow")
	}
}

// FailClosed: missing field, wrong type, etc.
func TestEvalPathClassify_FailsClosed(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field:   "parameters.path",
			Require: domain.PathRequire{CleanFirst: true, DeniedCanonicalPrefixes: []string{"/etc"}},
		},
	}
	// Missing field
	if !engine.EvalCondition(cond, map[string]interface{}{"tool_name": "os_read_file"}) {
		t.Errorf("did not fail-closed on missing parameters.path")
	}
	// Wrong type (int instead of string)
	if !engine.EvalCondition(cond, map[string]interface{}{"parameters.path": 42}) {
		t.Errorf("did not fail-closed on non-string parameters.path")
	}
}

// AllowedList semantics: when AllowedCanonicalPrefixes is set, ONLY
// paths under those prefixes pass. Everything else fires the rule.
func TestEvalPathClassify_AllowedList(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst:               true,
				AbsoluteOnly:             true,
				AllowedCanonicalPrefixes: []string{"/tmp/agent/", "/var/log/myapp/"},
			},
		},
	}
	// Under allowed prefix → pass (no fire)
	for _, p := range []string{
		"/tmp/agent/scratch.txt",
		"/var/log/myapp/today.log",
	} {
		if engine.EvalCondition(cond, pathFields(p)) {
			t.Errorf("allow-list path %q fired the rule", p)
		}
	}
	// Outside allowed prefix → fire (deny)
	for _, p := range []string{
		"/tmp/notes.txt", // /tmp/ alone is not in the allow list, only /tmp/agent
		"/etc/passwd",
		"/var/log/system.log",
	} {
		if !engine.EvalCondition(cond, pathFields(p)) {
			t.Errorf("path %q outside allow-list did not fire", p)
		}
	}
}

// Deep glob (**) — matches across zero or more components.
func TestEvalPathClassify_DeepGlob(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst: true,
				DeniedCanonicalPrefixes: []string{
					"/srv/**/secrets",  // anywhere under /srv ending in /secrets
					"/var/log/**/.git", // any nested .git under /var/log
					"/opt/**",          // anything under /opt
				},
			},
		},
	}
	deny := []string{
		"/srv/team-a/data/secrets",
		"/srv/secrets",
		"/srv/secrets/keys",
		"/var/log/myapp/repo/.git",
		"/var/log/.git",
		"/opt/anything",
		"/opt/a/b/c/d/e/f.txt",
	}
	for _, p := range deny {
		t.Run("deny/"+p, func(t *testing.T) {
			if !engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("did not fire on %q", p)
			}
		})
	}
	allow := []string{
		"/srv/team-a/data/public.json",
		"/var/log/myapp/run.log",
		"/tmp/anything",
	}
	for _, p := range allow {
		t.Run("allow/"+p, func(t *testing.T) {
			if engine.EvalCondition(cond, pathFields(p)) {
				t.Errorf("fired on %q", p)
			}
		})
	}
}

// Wildcards work for one path component.
func TestEvalPathClassify_Wildcard(t *testing.T) {
	cond := domain.Condition{
		PathClassify: &domain.PathClassify{
			Field: "parameters.path",
			Require: domain.PathRequire{
				CleanFirst:              true,
				DeniedCanonicalPrefixes: []string{"/home/*/.ssh"},
			},
		},
	}
	deny := []string{
		"/home/alice/.ssh/id_rsa",
		"/home/bob/.ssh/known_hosts",
		"/home/x/.ssh",
	}
	for _, p := range deny {
		if !engine.EvalCondition(cond, pathFields(p)) {
			t.Errorf("did not fire on %q", p)
		}
	}
	allow := []string{
		"/home/alice/Documents/notes.txt",
		"/home/.ssh/missing-user-segment", // pattern requires a user segment
		"/var/log/something",
	}
	for _, p := range allow {
		if engine.EvalCondition(cond, pathFields(p)) {
			t.Errorf("fired on %q", p)
		}
	}
}
