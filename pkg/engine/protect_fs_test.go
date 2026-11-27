package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFSLookupsSkipRemoteMounts: with a fake mount list, no lookup of the
// protect checks reaches the mount, by its path or through a link, and a
// write that reaches the mount is still denied.
func TestFSLookupsSkipRemoteMounts(t *testing.T) {
	netRemoteOnce.Do(loadRemoteMounts)
	saved := netRemoteMounts
	t.Cleanup(func() { netRemoteMounts = saved; fsTrace = nil })

	h, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", h)
	mnt := filepath.Join(h, "mnt")
	for _, d := range []string{filepath.Join(mnt, "sub"), filepath.Join(h, ".claude"), filepath.Join(h, "free")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(mnt, "x"), filepath.Join(mnt, "sub", "settings.json"), filepath.Join(h, ".claude", "settings.json")} {
		if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	links := [][2]string{
		{mnt, filepath.Join(h, "lnk")},
		{filepath.Join(h, "lnk", "sub"), filepath.Join(h, "deep")},
		{filepath.Join(mnt, "sub", "settings.json"), filepath.Join(h, "free", "alias")},
		{mnt, filepath.Join(h, ".claude", "out")},
		{"../lnk/sub", filepath.Join(h, "free", "rel")},
	}
	for _, l := range links {
		if err := os.Symlink(l[0], l[1]); err != nil {
			t.Fatal(err)
		}
	}
	netRemoteMounts = append(append([]string{}, saved...), strings.TrimRight(netInternal(filepath.ToSlash(mnt)), "/"))

	// inMount reports whether a lookup of p asks the mount: p, with the
	// links of its existing part followed, is at or under it.
	// For lstat and readlink, a link in the last part is not followed.
	inMount := func(op, p string) bool {
		if !filepath.IsAbs(p) {
			wd, _ := os.Getwd()
			p = filepath.Join(wd, p)
		}
		p = filepath.Clean(p)
		rest := ""
		if op == "lstat" || op == "readlink" {
			if p == mnt {
				return true
			}
			rest, p = filepath.Base(p), filepath.Dir(p)
		}
		for {
			if r, err := filepath.EvalSymlinks(p); err == nil {
				p = filepath.Join(r, rest)
				break
			}
			parent := filepath.Dir(p)
			if parent == p {
				break
			}
			rest = filepath.Join(filepath.Base(p), rest)
			p = parent
		}
		return p == mnt || strings.HasPrefix(p, mnt+string(filepath.Separator))
	}
	var bad []string
	fsTrace = func(op, p string) {
		if inMount(op, p) {
			bad = append(bad, op+" "+p)
		}
	}
	check := func(what string) {
		t.Helper()
		if len(bad) > 0 {
			t.Errorf("%s: lookups reached the mount: %q", what, bad)
			bad = nil
		}
	}

	// The lookup functions themselves.
	for _, p := range []string{filepath.Join(h, "lnk", "x"), filepath.Join(h, "deep", "settings.json"), filepath.Join(h, "free", "rel", "settings.json"), mnt} {
		if _, err := fsLstat(p); !errors.Is(err, errRemoteMount) {
			t.Errorf("fsLstat(%q) = %v, want errRemoteMount", p, err)
		}
		if _, err := fsStat(p); !errors.Is(err, errRemoteMount) {
			t.Errorf("fsStat(%q) = %v, want errRemoteMount", p, err)
		}
		if _, err := fsEvalSymlinks(p); !errors.Is(err, errRemoteMount) {
			t.Errorf("fsEvalSymlinks(%q) = %v, want errRemoteMount", p, err)
		}
		if _, err := fsReadDir(p); !errors.Is(err, errRemoteMount) {
			t.Errorf("fsReadDir(%q) = %v, want errRemoteMount", p, err)
		}
	}
	if _, err := fsStat(filepath.Join(h, "free", "alias")); !errors.Is(err, errRemoteMount) {
		t.Errorf("fsStat of a link into the mount = %v", err)
	}
	// The link itself is off the mount.
	if fi, err := fsLstat(filepath.Join(h, "lnk")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("fsLstat of the link = %v, %v", fi, err)
	}
	if target, err := fsReadlink(filepath.Join(h, "lnk")); err != nil || target != mnt {
		t.Errorf("fsReadlink of the link = %q, %v", target, err)
	}
	if r, err := fsEvalSymlinks(filepath.Join(h, "free", "..", ".claude", "settings.json")); err != nil || r != filepath.Join(h, ".claude", "settings.json") {
		t.Errorf("fsEvalSymlinks off the mount = %q, %v", r, err)
	}
	for _, pat := range []string{filepath.Join(h, "l*", "x"), filepath.Join(h, "*", "sub"), filepath.Join(h, "deep", "*"), filepath.Join(mnt, "*")} {
		if m, err := fsGlob(pat); err != nil || len(m) != 0 {
			t.Errorf("fsGlob(%q) = %q, %v", pat, m, err)
		}
	}
	if m, err := fsGlob(filepath.Join(h, "fr*", "*")); err != nil || len(m) != 2 {
		t.Errorf("fsGlob off the mount = %q, %v", m, err)
	}
	check("lookup functions")

	// A working directory on the mount: the name only.
	t.Chdir(mnt)
	t.Setenv("PWD", mnt)
	if wd, err := fsGetwd(); err != nil || wd != mnt {
		t.Errorf("fsGetwd on the mount = %q, %v", wd, err)
	}
	check("fsGetwd")
	t.Chdir(h)
	t.Setenv("PWD", h)

	prefixes := []string{filepath.Join(h, ".claude", "settings.json")}
	for _, c := range []struct {
		cmd  string
		deny int // 1 deny, 0 allow, -1 either
	}{
		{"cat lnk/x", 0},
		{"ls lnk", 0},
		{"cat deep/settings.json", 0},
		{"cat lnk/*", -1},
		{"ls */sub", -1},
		{"find lnk -name x", -1},
		{"echo x > lnk/sub/y", 1},
		{"cp a lnk/sub/settings.json", 1},
		{"cd lnk && touch y", 1},
		{"cd lnk; cd sub; echo x > ../z", 1},
		{"tee l*/s*/settings.json", 1},
		{"echo x > free/alias", 1},
		{"echo x > free/rel/settings.json", 1},
		{"D=lnk; cd $D; touch q", 1},
		{"tee {lnk,free}/a", 1},
		{"python3 w.py deep/../x", -1},
		{"ls " + mnt + "/sub", 0},
		{"touch .claude/out/x", 1},
		{"cp -r lnk/. ..", -1},
		{"pushd deep; rm settings.json", 1},
		{"cd ~ && ls", 0},
		{"echo x > lnk/{a,b}", 1},
		{"ls lnk/../free", -1},
		{"echo x > .claude/settings.json", 1},
		{"echo x > free/new", 0},
	} {
		for _, work := range [][]string{{h}, {mnt}, {filepath.Join(h, "deep")}} {
			hit, why := shellTouchesProtectedRec(c.cmd, prefixes, 0, nil, work)
			check(c.cmd + " in " + work[0])
			if work[0] != h {
				continue
			}
			if c.deny >= 0 && hit != (c.deny == 1) {
				t.Errorf("%q: deny=%v (%q), want %v", c.cmd, hit, why, c.deny == 1)
			}
		}
	}
	// A write from a working directory on the mount has its own reason.
	if hit, why := netCheck("touch a", prefixes, []string{mnt}); !hit || why != netRemoteCwdReason {
		t.Errorf("touch a in the mount: %v %q, want the reason %q", hit, why, netRemoteCwdReason)
	}
	if hit, why := netCheck("echo hi", prefixes, []string{mnt}); hit {
		t.Errorf("echo hi in the mount: denied (%q)", why)
	}
}
