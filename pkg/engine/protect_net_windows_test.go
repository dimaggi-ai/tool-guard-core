package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNetWindowsPathForms: the net reads the Windows forms of a path to a
// protected file: short 8.3 names, UNC paths, \\?\ paths, a path relative
// to the current directory of a drive (C:name), a path from the root of the
// current drive (\Users\x) and the Git bash form /c/Users/x.
func TestNetWindowsPathForms(t *testing.T) {
	h := t.TempDir()
	if err := os.MkdirAll(filepath.Join(h, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h, ".claude", "settings.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{file}
	vol := filepath.VolumeName(h)
	if len(vol) != 2 || vol[1] != ':' {
		t.Fatalf("temp dir %q is not on a drive", h)
	}
	noDrive := h[2:]
	gitBash := "/" + strings.ToLower(vol[:1]) + filepath.ToSlash(noDrive)
	cases := []struct {
		cmd  string
		deny bool
	}{
		{`echo x > \\server\share\x`, true},
		{`cp a \\server\share\x`, true},
		{`echo x > "\\localhost\C$\x\settings.json"`, true},
		{`echo x > "\\?\UNC\localhost\C$\x\settings.json"`, true},
		{`echo x > "\\?\` + file + `"`, true},
		{`echo x > "//?/` + filepath.ToSlash(file) + `"`, true},
		{`echo x > "\\.\` + file + `"`, true},
		{`echo x > ` + vol + `.claude\settings.json`, true},
		{`echo x > "` + vol + `.claude/settings.json"`, true},
		{`echo x > "` + noDrive + `\.claude\settings.json"`, true},
		{`python3 w.py "` + noDrive + `\.claude\settings.json"`, true},
		{`echo x > ` + gitBash + `/.claude/settings.json`, true},
		{`echo x > "` + gitBash + `/.claude/settings.json"`, true},
		// Controls.
		{`echo hi`, false},
		{`echo x > "` + h + `\free.txt"`, false},
		{`cat "` + file + `"`, false},
		// A glob gives only names a directory has, and no Windows name
		// holds a colon: * is no drive-relative path C:name.
		{`chmod 644 *.txt`, false},
		{`find . -name '*.go' | xargs grep foo`, false},
	}
	// The short 8.3 names, when the volume makes them.
	short := ""
	for s, long := range netShortNames(h) {
		if long == ".claude" {
			short = s
		}
	}
	if short != "" {
		cases = append(cases, []struct {
			cmd  string
			deny bool
		}{
			{`echo x > "` + filepath.Join(h, short, "settings.json") + `"`, true},
			{`echo x > ` + short + `\settings.json`, true},
			{`echo x > ` + strings.ToLower(short) + `/settings.json`, true},
			{`tee ` + short[:len(short)-1] + `{1,2,3}/settings.json`, true},
		}...)
	} else {
		t.Log("the volume makes no short 8.3 names: the short-name rows do not run")
	}
	if fileShort := netShortNames(filepath.Join(h, ".claude"))["SETTIN~1.JSO"]; fileShort == "settings.json" {
		cases = append(cases, struct {
			cmd  string
			deny bool
		}{`echo x > .claude\SETTIN~1.JSO`, true})
	}
	for _, c := range cases {
		hit, why := shellTouchesProtectedRec(c.cmd, prefixes, 0, nil, []string{h})
		if hit != c.deny {
			t.Errorf("%q: deny=%v (%q), want %v", c.cmd, hit, why, c.deny)
		}
	}
}
