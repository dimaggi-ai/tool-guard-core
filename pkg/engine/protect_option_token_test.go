package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: an option token ("-rf") must not be canonicalized as a relative
// path operand. Before the fix, running any mutating command with flags while
// the process CWD sat INSIDE a protected prefix fabricated "<cwd>/-rf" and
// produced a false-positive deny (found live: `rm -rf /tmp/foo` denied as
// "targets <policydir>/-rf" when the hook ran from the policy dir).
func TestShellOptionTokens_NotPathOperands(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(protected); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	prefixes := []string{protected}

	// Flags must not deny when the target is elsewhere.
	for _, cmd := range []string{
		"rm -rf /tmp/foo",
		"cp -a /tmp/a /tmp/b",
		"git commit -m protected-sounding-message",
	} {
		if hit, reason := ViolatesProtectedPaths(envCmd("bash", cmd), prefixes); hit {
			t.Errorf("%q: option token false-positive (reason=%q)", cmd, reason)
		}
	}

	// Real protected targets must still deny: positional, after --, and glued
	// path-options.
	for _, cmd := range []string{
		"rm " + protected + "/x.yaml",
		"rm -rf " + protected,
		"rm -- " + protected + "/x.yaml",
		"cp /tmp/a --target-directory=" + protected,
	} {
		if hit, _ := ViolatesProtectedPaths(envCmd("bash", cmd), prefixes); !hit {
			t.Errorf("%q: expected protected-path violation, got none", cmd)
		}
	}
}
