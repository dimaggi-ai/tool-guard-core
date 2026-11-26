package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReview090LinkBraceDenial is the positive control for the cost
// measurement of the long brace-list rule. The variable is what stands under
// the name in front of "..": a symbolic link into the protected directory, or
// a plain directory. The size of the list is held fixed. With the link the
// word reaches the protected file through it and must be denied; without the
// link the same word names only a file outside it and must not be.
func TestReview090LinkBraceDenial(t *testing.T) {
	// build makes home/.claude with settings.json, a working directory
	// home/cwd, and either a symbolic link home/lnk into .claude/sub or a
	// plain directory of that name.
	build := func(t *testing.T, withLink bool) (home, file string) {
		t.Helper()
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		home = filepath.Join(root, "home")
		cdir := filepath.Join(home, ".claude")
		if err := os.MkdirAll(filepath.Join(cdir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		file = filepath.Join(cdir, "settings.json")
		if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(home, "cwd"), 0o755); err != nil {
			t.Fatal(err)
		}
		// In the working directory stands a plain file of the same name, so
		// a ".." after that name leads back to the working directory itself.
		if err := os.WriteFile(filepath.Join(home, "cwd", "lnk"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if withLink {
			if err := os.Symlink(filepath.Join(cdir, "sub"), filepath.Join(home, "lnk")); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.MkdirAll(filepath.Join(home, "lnk"), 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	word := "lnk/../settings.{json,{1..70}}" // 70 words: above maxBraceWords
	cmd := "python3 w.py " + word

	for _, withLink := range []bool{true, false} {
		name := "plain directory"
		if withLink {
			name = "link into the protected directory"
		}
		t.Run(name, func(t *testing.T) {
			home, file := build(t, withLink)
			saved, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(filepath.Join(home, "cwd")); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chdir(saved); err != nil {
					t.Fatal(err)
				}
			}()
			prefixes := []string{filepath.ToSlash(file)}
			bases := []string{filepath.ToSlash(home), filepath.ToSlash(filepath.Join(home, "cwd"))}
			unread := unreadWord(cmd, tokenizeShell(cmd), bases, prefixes)
			hit, _ := shellTouchesProtectedRec(cmd, prefixes, 0, nil, bases)
			named := commandNamesProtected(tokenizeShell(cmd), []string{word}, bases, nil, nil, prefixes)
			if withLink {
				if unread == "" {
					t.Errorf("unreadWord allowed the word, want denied")
				}
				if !hit {
					t.Errorf("the command was allowed, want denied")
				}
				return
			}
			// Under both bases the word names a file outside the
			// protected directory: home/settings.json, and nothing under
			// the plain file cwd/lnk.
			if named != "" {
				t.Errorf("the name rule read %s, want nothing", named)
			}
			if unread != "" {
				t.Errorf("unreadWord read %s, want nothing", unread)
			}
			if hit {
				t.Errorf("the command was denied, want allowed")
			}
		})
	}
}
