package engine

import (
	"strings"
	"testing"
)

// This file is the adversarial suite for the real shell tokenizer that
// replaced the best-effort scanner (shell_tokenize.go + protect.go). It works
// at two levels: direct unit tests of tokenizeShell / splitShellSegments, and
// behavioral tests of shellTouchesProtected against /protected (reusing the
// package-level testPrefixes from protect_test.go). Every case that the OLD
// scanner's own doc comment admitted it could not catch is exercised here and
// proven to be either resolved outright or failed closed.

// wordVals returns the resolved literal of each word token, in order.
func wordVals(toks []shellToken) []string {
	var out []string
	for _, t := range toks {
		if t.kind == tokWord {
			out = append(out, t.value)
		}
	}
	return out
}

// nthWord returns the i-th word token (skipping operators).
func nthWord(toks []shellToken, i int) shellToken {
	n := 0
	for _, t := range toks {
		if t.kind == tokWord {
			if n == i {
				return t
			}
			n++
		}
	}
	return shellToken{}
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Tokenizer unit tests ───────────────────────────────────────────────────

// Quoting and escaping: adjacent quoted/unquoted pieces form ONE word, a
// separator inside quotes is literal, and backslash escapes survive.
func TestTokenizeShell_WordsAndQuoting(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string // expected word values in order
	}{
		{"concatenated single-quote", "rm '/prot'ected/f", []string{"rm", "/protected/f"}},
		{"concatenated double-quote", `rm "/protected/"f`, []string{"rm", "/protected/f"}},
		{"empty single-quote splice", "r''m /x", []string{"rm", "/x"}},
		{"semicolon inside dquotes", `echo "a;b"`, []string{"echo", "a;b"}},
		{"pipe inside squotes", `echo 'a|b'`, []string{"echo", "a|b"}},
		{"literal dquote in squotes", `echo 'a"b'`, []string{"echo", `a"b`}},
		{"literal squote path", `rm '/protected/a"b'`, []string{"rm", `/protected/a"b`}},
		{"escaped space keeps one word", `rm /protected/a\ b`, []string{"rm", "/protected/a b"}},
		{"escaped quote is literal", `rm /protected/a\"b`, []string{"rm", `/protected/a"b`}},
		{"dquote var syntax literal-ish", `echo "$x"`, []string{"echo", ""}}, // $x elided, unresolved
		{"single-quote var is literal", `echo '$x'`, []string{"echo", "$x"}},
		{"lone dollar is literal", `echo price$`, []string{"echo", "price$"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wordVals(tokenizeShell(tc.cmd))
			if !eqStrs(got, tc.want) {
				t.Errorf("tokenizeShell(%q) words = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// The unresolved flag is set exactly when a word carries a substitution or
// variable expansion we cannot evaluate — and NOT for single-quoted literals.
func TestTokenizeShell_UnresolvedFlag(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		wordIdx int
		want    bool
	}{
		{"command subst $()", "rm $(echo x)", 1, true},
		{"backtick subst", "rm `echo x`", 1, true},
		{"variable $VAR", "rm $VAR", 1, true},
		{"variable ${VAR}", "rm ${VAR}", 1, true},
		{"var inside dquotes", `rm "$VAR"`, 1, true},
		{"subst inside dquotes", `rm "$(id)"`, 1, true},
		{"arithmetic $(( ))", "rm file$((1+1))", 1, true},
		{"special param $?", "echo $?", 1, true},
		{"var in single quotes NOT unresolved", "rm '$VAR'", 1, false},
		{"lone dollar NOT unresolved", "echo cost$", 1, false},
		{"plain path NOT unresolved", "rm /protected/f", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := nthWord(tokenizeShell(tc.cmd), tc.wordIdx)
			if w.unresolved != tc.want {
				t.Errorf("tokenizeShell(%q) word[%d]=%q unresolved=%v, want %v", tc.cmd, tc.wordIdx, w.value, w.unresolved, tc.want)
			}
		})
	}
}

// A separator inside quotes must NOT create a new segment; a real separator
// must. This is the exact bug the non-quote-aware FieldsFunc split had.
func TestTokenizeShell_SegmentsQuoteAware(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want int // expected segment count
	}{
		{"quoted semicolon → one segment", `echo "a;b"`, 1},
		{"real semicolon → two segments", "echo a;b", 2},
		{"quoted pipe → one segment", `echo 'a|b' c`, 1},
		{"real pipe → two segments", "cat x | tee y", 2},
		{"real && → two segments", "ls /etc && echo hi", 2},
		{"subshell parens split", "(rm /protected/f)", 1}, // parens are separators; inner is its own segment
		{"quoted sep then real redirect", `echo "a;b" > /protected/f`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := len(splitShellSegments(tokenizeShell(tc.cmd)))
			if got != tc.want {
				t.Errorf("splitShellSegments(%q) = %d segments, want %d", tc.cmd, got, tc.want)
			}
		})
	}
}

// Redirect operator recognition, including leading-fd binding and the fd-dup
// vs file distinction.
func TestTokenizeShell_Redirects(t *testing.T) {
	// echo x 2> f : the 2 binds to the redirect, target is f.
	toks := tokenizeShell("echo x 2> /protected/f")
	tgts := redirectTargets(toks)
	if len(tgts) != 1 || tgts[0].value != "/protected/f" {
		t.Errorf("`echo x 2> /protected/f`: redirect targets = %+v, want one target /protected/f", tgts)
	}
	// 2>&1 is a pure fd dup — no file write target.
	if got := redirectTargets(tokenizeShell("echo x 2>&1")); len(got) != 0 {
		t.Errorf("`2>&1` produced write targets %+v, want none (fd dup)", got)
	}
	// >&- closes an fd, not a file.
	if got := redirectTargets(tokenizeShell("echo x >&-")); len(got) != 0 {
		t.Errorf("`>&-` produced write targets %+v, want none (fd close)", got)
	}
	// >& file (non-fd operand) IS a bash file write.
	if got := redirectTargets(tokenizeShell("echo x >& /protected/f")); len(got) != 1 || got[0].value != "/protected/f" {
		t.Errorf("`>& /protected/f`: targets = %+v, want /protected/f", got)
	}
	// Input redirection is never a write target.
	if got := redirectTargets(tokenizeShell("cat < /protected/in")); len(got) != 0 {
		t.Errorf("`< /protected/in` produced write targets %+v, want none (input)", got)
	}
}

// ── Behavioral: shellTouchesProtected against /protected ────────────────────

func mustFire(t *testing.T, cmd string) {
	t.Helper()
	if hit, _ := shellTouchesProtected(cmd, testPrefixes); !hit {
		t.Errorf("BYPASS: %q must be caught (or fail closed) but did not fire", cmd)
	}
}

func mustNotFire(t *testing.T, cmd string) {
	t.Helper()
	if hit, target := shellTouchesProtected(cmd, testPrefixes); hit {
		t.Errorf("OVERBLOCK: %q must NOT fire but did (target=%q)", cmd, target)
	}
}

// The adversarial evasions the task requires, each proven caught or failed
// closed.
func TestShellTouchesProtected_Adversarial(t *testing.T) {
	fire := []struct{ name, cmd string }{
		// Nested/mixed quoting: single-quoted path containing a literal ".
		{"squoted path with dquote char", `rm '/protected/a"b'`},
		// Quoted separator followed by a REAL redirect after the closing quote:
		// the fake ; inside quotes must not break the command, the real > must
		// still be detected.
		{"quoted-sep then real redirect", `echo "a;b" > /protected/f`},
		// Command substitution used to construct a path argument to rm.
		{"cmd subst path to rm", `rm $(echo /protected/f)`},
		// Backtick substitution doing the same.
		{"backtick subst path to rm", "rm `echo /protected/f`"},
		// Variable expansion in a path argument to rm, both forms.
		{"var $VAR path to rm", "rm $PROTECTED/f"},
		{"var ${VAR} path to rm", "rm ${PROTECTED}/f"},
		// Backslash-escaped space / quote inside a protected path arg.
		{"escaped space path to rm", `rm /protected/a\ b`},
		{"escaped quote path to rm", `rm /protected/a\"b`},
		// Concatenated quoting (old unquote() could only strip one pair).
		{"concatenated quoting to rm", `rm '/prot'ected/f`},
		// Redirect target built from an expansion → fail closed.
		{"redirect target is a var", `echo x > $DIR/f`},
		{"redirect target is cmd subst", `echo x > $(echo /protected/f)`},
	}
	for _, c := range fire {
		t.Run("fire/"+c.name, func(t *testing.T) { mustFire(t, c.cmd) })
	}

	nofire := []struct{ name, cmd string }{
		// Benign command on a non-protected path.
		{"ls -la /tmp", "ls -la /tmp"},
		// Reading a protected file is allowed (cat is not mutating).
		{"cat protected", "cat /protected/policy.yaml"},
		// A variable NOT in a path-check position must not fail closed.
		{"echo $HOME", "echo $HOME"},
		{"grep with var non-mutating", "grep $PATTERN /var/log/app.log"},
		// A quoted separator alone must not fire (echo is not mutating and the
		// ; is inside quotes, so there is no second segment).
		{"quoted sep alone", `echo "a;b"`},
		// A redirect operator that lives INSIDE quotes is not a real redirect —
		// the old byte scanner false-fired here; the tokenizer correctly does not.
		{"quoted redirect is not real", `echo '> /protected/f'`},
		// Writes to an unprotected path.
		{"rm unprotected", "rm /tmp/scratch.txt"},
		{"echo redirect unprotected", "echo hello > /tmp/out.txt"},
		// Input-redirect operand is read, not written: only the (unprotected)
		// tee target is a write, so this must not fire on the protected input.
		{"input redirect not a write", "tee /tmp/out < /protected/in"},
	}
	for _, c := range nofire {
		t.Run("nofire/"+c.name, func(t *testing.T) { mustNotFire(t, c.cmd) })
	}
}

// The fail-closed is scoped to path-check positions: an unresolved token only
// forces a hit when it is a redirect target or an argument to a mutating
// command. Elsewhere it passes. (cp's source arg is intentionally over-
// approximated to a hit — all args of a mutating prog are treated uniformly,
// the safe direction, matching the pre-existing model.)
func TestShellTouchesProtected_FailClosedScoping(t *testing.T) {
	mustNotFire(t, "echo $HOME")        // echo not mutating, no redirect
	mustNotFire(t, "printf %s $UNSET")  // printf not mutating
	mustFire(t, "rm $HOME/x")           // unresolved arg to mutating rm
	mustFire(t, "cp $SRC /tmp/dst")     // unresolved arg to mutating cp (over-approx, safe)
	mustFire(t, "truncate -s0 $TARGET") // unresolved arg to truncate
}

// Explicit strict-superset verification (task requirement 4): every real-write
// shape the OLD scanner caught must STILL fire under the tokenizer.
func TestShellTouchesProtected_SupersetOfOldScanner(t *testing.T) {
	oldCaughtRealWrites := []string{
		// Redirections the old byte scanner caught.
		"echo x > /protected/f",
		"printf '%s\\n' stuff >> /protected/policy.yaml",
		"echo x >/protected/f;ls", // redirect immediately before a separator
		"echo x 2> /protected/f",  // fd-prefixed redirect
		"echo x &> /protected/f",  // both-streams redirect (old saw the '>')
		"cat x <> /protected/f",   // read-write open (old saw the '>')
		// Mutating commands the old scanner caught.
		"rm /protected/f",
		"cp a /protected/f",
		"mv a /protected/f",
		"tee /protected/f",
		"truncate -s0 /protected/f",
		"ln -s a /protected/f",
		"touch /protected/f",
		"chmod 600 /protected/f",
		"chown root /protected/f",
		"mkdir /protected/newdir",
		"sed -i s/a/b/ /protected/f",
		"dd if=/dev/urandom of=/protected/f bs=512 count=1",
		"cat /dev/stdin | tee /protected/policy.yaml", // pipeline segment
	}
	for _, cmd := range oldCaughtRealWrites {
		t.Run("superset/"+cmd, func(t *testing.T) { mustFire(t, cmd) })
	}

	// Real writes the OLD scanner MISSED (not quote-aware) that the tokenizer
	// now catches — strictly better, and none of these are false positives.
	nowAlsoCaught := []string{
		`rm "/protected/a;b"`, // quoted ';' mangled the old naive Fields split
		"(rm /protected/f)",   // subshell prog was "(rm" to the old scanner
		`rm '/prot'ected/f`,   // concatenated quoting
	}
	for _, cmd := range nowAlsoCaught {
		t.Run("improved/"+cmd, func(t *testing.T) { mustFire(t, cmd) })
	}
}

// The three evasions the OLD protect.go doc comment explicitly admitted to
// ("quoting, command substitution, variable expansion ... a determined agent
// can evade it"), each proven now caught or failed closed. (Mirrors the
// rewritten TestViolatesProtectedPaths_FormerlyUncaughtNowFailClosed but at the
// shellTouchesProtected level and with more forms.)
func TestShellTouchesProtected_OldDocEvasionsNowCaught(t *testing.T) {
	evasions := map[string]string{
		"variable expansion":     "rm $POLICY_DIR/rules.yaml",     // fail closed
		"brace variable":         "rm ${POLICY_DIR}/rules.yaml",   // fail closed
		"command substitution":   `dd of=$(echo /protected/f)`,    // fail closed
		"backtick substitution":  "cp `echo /protected/f` /tmp/x", // fail closed
		"concatenated quoting":   "rm '/prot'ected/f",             // resolved outright
		"tilde-free mixed quote": `rm "/prot""ected"/f`,           // resolved outright
	}
	for name, cmd := range evasions {
		t.Run(name, func(t *testing.T) { mustFire(t, cmd) })
	}
}

// Hardening beyond the base spec: a mutating command hidden behind a leading
// variable assignment is still detected, and bash ANSI-C / locale quoting of a
// path fails closed instead of slipping past as a literal.
func TestShellTouchesProtected_HardeningEvasions(t *testing.T) {
	fire := []struct{ name, cmd string }{
		{"assignment prefix + rm", "FOO=bar rm /protected/f"},
		{"multiple assignment prefixes", "A=1 B=2 rm /protected/f"},
		{"assignment prefix + redirect", "FOO=bar echo x > /protected/f"},
		{"ansi-c encoded path fails closed", `rm $'\x2fprotected\x2ff'`},
		{"locale-quoted path fails closed", `rm $"/protected/f"`},
	}
	for _, c := range fire {
		t.Run("fire/"+c.name, func(t *testing.T) { mustFire(t, c.cmd) })
	}
	nofire := []struct{ name, cmd string }{
		// Assignment prefix in front of a non-mutating command must not fire.
		{"assignment + ls not mutating", "FOO=bar ls /protected"},
		{"assignment + cat read", "LANG=C cat /protected/policy.yaml"},
	}
	for _, c := range nofire {
		t.Run("nofire/"+c.name, func(t *testing.T) { mustNotFire(t, c.cmd) })
	}
}

// Regression tests for the three bypasses an adversarial review found:
//
//	F1 — bash ANSI-C $'\'' must not swallow a following real redirect.
//	F2 — cp/mv/ln/install glued target-directory options that write into a
//	     protected dir.
//	F3 — a write hidden inside a command substitution whose output is discarded.
func TestShellTouchesProtected_ReviewRegressions(t *testing.T) {
	fire := []struct{ name, cmd string }{
		// F1: the escaped quote in $'\'' ends the ANSI-C region correctly, so
		// the trailing `> /protected/f` is a real redirect and must be seen.
		// (argv0 echo is non-mutating, so only correct redirect parsing catches it.)
		{"F1 ansi-c quote then redirect", `echo $'\'' > /protected/f`},
		{"F1 ansi-c quote then append", `printf x $'\'' >> /protected/config`},
		// F2: destination directory glued into the option word.
		{"F2 cp --target-directory=", "cp secret.txt --target-directory=/protected"},
		{"F2 cp --target abbrev", "cp secret.txt --target-dir=/protected"},
		{"F2 cp -t glued", "cp secret.txt -t/protected"},
		{"F2 mv --target-directory=", "mv secret.txt --target-directory=/protected"},
		{"F2 install -t glued", "install secret.txt -t/protected"},
		{"F2 cp combined -rt", "cp -rt/protected secret.txt"},
		// F3: command substitution executes rm for its side effect.
		{"F3 echo $(rm ...)", "echo $(rm /protected/secret)"},
		{"F3 backtick rm", "echo `rm /protected/secret`"},
		{"F3 assignment $(rm ...)", "x=$(rm /protected/secret)"},
		{"F3 nested subst", "echo $(echo $(rm /protected/secret))"},
		{"F3 subst in dquotes", `echo "$(rm /protected/secret)"`},
	}
	for _, c := range fire {
		t.Run("fire/"+c.name, func(t *testing.T) { mustFire(t, c.cmd) })
	}
	nofire := []struct{ name, cmd string }{
		// F3 precision: a substitution that only READS must not fire.
		{"F3 read-only subst", "echo $(cat /protected/secret)"},
		{"F3 benign subst", "echo $(date)"},
		{"F3 assignment read", "x=$(ls /protected)"},
		// F2 precision: -t as a bare flag (path is next word, unprotected).
		{"F2 -t unprotected", "cp -t /tmp secret.txt"},
		// F3 precision: a substitution inside SINGLE quotes is literal, never
		// executed, so it must not be recursed into.
		{"F3 single-quoted subst literal", `echo '$(rm /protected/f)'`},
	}
	for _, c := range nofire {
		t.Run("nofire/"+c.name, func(t *testing.T) { mustNotFire(t, c.cmd) })
	}
}

// Malformed / pathological input must never panic and must degrade safely.
func TestTokenizeShell_MalformedNoPanic(t *testing.T) {
	inputs := []string{
		"",
		"   ",
		"rm 'unterminated",
		`rm "unterminated`,
		"rm $(unterminated",
		"rm ${unterminated",
		"rm `unterminated",
		`rm trailing\`,
		";;;;",
		">>>",
		"| | |",
		"$",
		"${}",
		"$()",
		strings.Repeat("a ", 5000),
		strings.Repeat("$(", 200) + strings.Repeat(")", 200),
	}
	for _, in := range inputs {
		// Must not panic; result value is irrelevant here.
		_ = tokenizeShell(in)
		_, _ = shellTouchesProtected(in, testPrefixes)
	}
}
