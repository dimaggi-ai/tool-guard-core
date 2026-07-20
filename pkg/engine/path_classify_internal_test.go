package engine

import "testing"

// matchPathPrefix backs path_classify, write_classify, shell_classify's argv
// path lists, and -protect-self/-protect-paths — a single unnormalized
// comparison here would break allow/deny path prefixes on every one of them
// on Windows, since canonicalCandidates() produces "\"-separated paths there
// while every policy prefix in this repo (and every doc example) is authored
// with "/". These tests exercise the normalization directly against
// hand-built backslash strings, so they catch a regression on any OS —
// not just when actually run on a Windows CI runner.
func TestMatchPathPrefix_WindowsSeparatorNormalization(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		prefix string
		want   bool
	}{
		{"backslash path, forward-slash prefix, dir match", `C:\workspace\file.txt`, "C:/workspace/", true},
		{"backslash path, forward-slash prefix, exact deny target", `C:\etc\shadow`, "C:/etc/shadow", true},
		{"backslash path outside prefix", `C:\other\file.txt`, "C:/workspace/", false},
		{"backslash path, single-component wildcard prefix", `C:\home\alice\.ssh\id_rsa`, "C:/home/*/.ssh", true},
		{"backslash path, deep-glob prefix", `C:\srv\team-a\data\secrets`, "C:/srv/**/secrets", true},
		{"both operands backslash (prefix authored on Windows too)", `C:\workspace\file.txt`, `C:\workspace\`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matchPathPrefix(c.path, c.prefix)
			if got != c.want {
				t.Errorf("matchPathPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
			}
		})
	}
}

// A literal "\" is a legal Unix filename character. Normalizing it
// unconditionally (an earlier version of this fix did exactly that) turns a
// sibling file's name into a fake path separator, misclassifying it as
// living inside a directory it never actually touches — a real allow-list
// bypass on Unix, not a theoretical one. The gate must confine
// backslash-as-separator treatment to operands actually shaped like an
// absolute Windows path (drive-letter or UNC), never a bare Unix path.
func TestMatchPathPrefix_LiteralBackslashInUnixFilenameIsNotASeparator(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		prefix string
		want   bool
	}{
		{
			"sibling file whose name contains a backslash must not be treated as living under the prefix",
			`/home/alice/documents\secrets.txt`, "/home/alice/documents/", false,
		},
		{
			"a real file actually inside the allowed dir still matches",
			"/home/alice/documents/secrets.txt", "/home/alice/documents/", true,
		},
		{
			"backslash-containing filename with a wildcard prefix still doesn't spuriously match",
			`/home/alice/.ssh\backup`, "/home/*/.ssh", false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matchPathPrefix(c.path, c.prefix)
			if got != c.want {
				t.Errorf("matchPathPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
			}
		})
	}
}
