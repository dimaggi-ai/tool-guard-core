package engine

import (
	"strings"
	"testing"
)

// TestTokenizeShellZshOperatorsKeepTheBashReading: the policy classifiers
// read a command with tokenizeShell, the bash reading of 22ed838. In it the
// write operators of zsh and fish (>? >! >>! &>! &>>!) are the bash
// operator and a file named by the rest, so `rm >? -rf /` keeps the words
// rm -rf /. Only the protected-path check reads them as zsh does, with
// tokenizeShellZsh.
func TestTokenizeShellZshOperatorsKeepTheBashReading(t *testing.T) {
	ops := []struct{ zsh, bash string }{
		{">?", `> '?'`},
		{">!", `> '!'`},
		{">>!", `>> '!'`},
		{"&>!", `&> '!'`},
		{"&>>!", `&>> '!'`},
	}
	bases := []string{"rm %s -rf /", "rm%s -rf /", "dd if=/dev/zero %s of=/dev/sda"}
	for _, op := range ops {
		for _, b := range bases {
			zcmd := strings.Replace(b, "%s", op.zsh, 1)
			bcmd := strings.Replace(b, "%s", op.bash, 1)
			z, bash := tokenizeShell(zcmd), tokenizeShell(bcmd)
			if len(z) != len(bash) {
				t.Errorf("tokenizeShell(%q) gives %d tokens, its bash reading %q gives %d", zcmd, len(z), bcmd, len(bash))
				continue
			}
			for i := range z {
				if z[i].kind != bash[i].kind || z[i].value != bash[i].value {
					t.Errorf("tokenizeShell(%q) token %d is %v %q, its bash reading %q has %v %q",
						zcmd, i, z[i].kind, z[i].value, bcmd, bash[i].kind, bash[i].value)
				}
			}
			// The zsh reading takes the whole operator, and the next
			// word is the file written.
			zz := tokenizeShellZsh(zcmd)
			found := false
			for i := 0; i+1 < len(zz); i++ {
				if zz[i].kind == tokRedirWrite && zz[i+1].kind == tokWord {
					found = true
					if want := strings.Fields(b[strings.Index(b, "%s")+2:])[0]; zz[i+1].value != want {
						t.Errorf("tokenizeShellZsh(%q) writes %q, want %q", zcmd, zz[i+1].value, want)
					}
					break
				}
			}
			if !found {
				t.Errorf("tokenizeShellZsh(%q) has no write redirection", zcmd)
			}
		}
	}
}
