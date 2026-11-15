package engine

import (
	"path/filepath"
	"testing"
)

func TestProtectedShellUsesHOME(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", t.TempDir())
	prefixes := []string{filepath.Join(home, "protected")}
	for _, cmd := range []string{
		"echo x > ~/protected/new",
		"rm $HOME/protected/new",
		"cd ~ && rm protected/new",
		"rm ~/protect*/new",
		"python edit.py ${HOME}/protected/new",
	} {
		if hit, reason := shellTouchesProtected(cmd, prefixes); !hit {
			t.Errorf("%q: hit = false (%s)", cmd, reason)
		}
	}
	if hit, reason := shellTouchesProtected("echo x > ~/unprotected/new", prefixes); hit {
		t.Errorf("unprotected write denied: %s", reason)
	}
}
