package main

// Fifth-round regression tests for PR #93: every finding of the round-4
// reviews (2026-11-26) with its variants, the bypasses B1-B16 found against
// the round-5 design, the ordinary commands that must not be denied, and
// the pathological inputs that must end fast. Every case runs through the
// hook with the shipped policy, once with the hook process in the event cwd
// and once in another temporary directory.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// review090eTree extends review090dTree with the links and directories the
// round-5 cases need. tg is a protected directory beside the protected
// file; evil is a directory that holds a file named settings.json.
func review090eTree(t *testing.T) (home, cdir, file, tg, evil string, dirs []string) {
	t.Helper()
	home, cdir, file, dirs = review090dTree(t)
	links := map[string]string{
		"my link":    cdir,
		"{x}":        cdir,
		"a,b":        cdir,
		"free/alias": file,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"sub", "repo", "build", ".tool-guard"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tg = filepath.Join(home, ".tool-guard")
	if err := os.WriteFile(filepath.Join(tg, "protect-paths"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	evil = filepath.Join(t.TempDir(), "evil")
	if err := os.MkdirAll(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evil, "settings.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, cdir, file, tg, evil, dirs
}

// review090eRaw runs the hook on a raw JSON event with the given policy and
// protected paths.
func review090eRaw(t *testing.T, raw []byte, pol string, protect []string, extra ...string) (decision, reason string) {
	t.Helper()
	abs, err := filepath.Abs(pol)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-policy", abs, "-mode", "enforcement", "-fail-closed"}
	for _, p := range protect {
		args = append(args, "-protect-path", p)
	}
	args = append(args, extra...)
	var buf bytes.Buffer
	if code := runHook(args, bytes.NewReader(raw), &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(buf.String()) == "" {
		return "", ""
	}
	return hookDecisionReason(t, buf.String())
}

// review090eCase is one hook call. ev is marshalled unless raw is set.
type review090eCase struct {
	name    string
	ev      map[string]interface{}
	raw     string
	pol     string   // policy path; the shell policy when empty
	protect []string // protected paths; the protected file when empty
	extra   []string // more hook flags
}

func (c review090eCase) payload(t *testing.T) []byte {
	t.Helper()
	if c.raw != "" {
		return []byte(c.raw)
	}
	b, err := json.Marshal(c.ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// review090eEach runs check for every case twice: with the hook process in
// the event cwd (home when the event has none) and in another directory.
func review090eEach(t *testing.T, home, file string, cases []review090eCase, check func(t *testing.T, got, reason string, took time.Duration)) {
	t.Helper()
	other := t.TempDir()
	for _, c := range cases {
		c := c
		eventDir := home
		if c.ev != nil {
			if cwd, ok := c.ev["cwd"].(string); ok && cwd != "" {
				eventDir = cwd
			}
		}
		for _, hc := range []struct{ name, dir string }{{"hook in event cwd", eventDir}, {"hook in other dir", other}} {
			hc := hc
			t.Run(c.name+"/"+hc.name, func(t *testing.T) {
				t.Chdir(hc.dir)
				pol := c.pol
				if pol == "" {
					pol = review090bShellPolicy()
				}
				// The policy path is relative to the package directory.
				if !filepath.IsAbs(pol) {
					pol = filepath.Join(review090ePkgDir, pol)
				}
				protect := c.protect
				if len(protect) == 0 {
					protect = []string{file}
				}
				start := time.Now()
				got, reason := review090eRaw(t, c.payload(t), pol, protect, c.extra...)
				check(t, got, reason, time.Since(start))
			})
		}
	}
}

// review090ePkgDir is the package directory, read before any test changes
// the working directory.
var review090ePkgDir = func() string {
	d, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return d
}()

func TestReview090eBypasses(t *testing.T) {
	home, cdir, file, tg, evil, dirs := review090eTree(t)
	L := "{json,{1..70}}"
	sh := func(cmd string) review090eCase { return review090eCase{name: cmd, ev: bashEv(cmd, home)} }
	shIn := func(cwd, cmd string) review090eCase {
		return review090eCase{name: cmd + " (cwd " + filepath.Base(cwd) + ")", ev: bashEv(cmd, cwd)}
	}
	named := func(name string, c review090eCase) review090eCase { c.name = name; return c }
	dirs35 := strings.Join(dirs[:35], " ")
	// Gemini r4 6: a patch nested 18 levels deep whose markers are JSON
	// escapes.
	esc := `\u002a\u002a\u002a`
	deepRaw := `{"patch":"` + esc + ` Begin Patch\n` + esc + ` Update File: ` + file + `\n@@\n+x\n` + esc + ` End Patch"}`
	for i := 0; i < 18; i++ {
		deepRaw = `{"a":` + deepRaw + `}`
	}
	deepRaw = `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","cwd":"/tmp","tool_input":` + deepRaw + `}`
	b6 := `eval "tee .claude/\$'\\""x73\\""x65\\""x74\\""x74\\""x69\\""x6e\\""x67\\""x73\\""x2e\\""x6a\\""x73\\""x6f\\""x6e'" <<< pwn`
	tgOnly := []string{tg}
	z62 := strings.Repeat("0", 62)
	cases := []review090eCase{
		// Fable r4 1: a quoted or escaped long list handed to a command
		// that reads its text again.
		sh(`eval tee '.claude/settings.` + L + `'`),
		sh(`eval tee ".claude/settings.` + L + `"`),
		sh(`eval tee .claude/settings.\{json,{1..70}\}`),
		sh(`bash -c 'eval tee ".claude/settings.` + L + `"'`),
		sh(`eval tee '$HOME/.claude/settings.` + L + `'`),
		sh(`xargs -I% sh -c 'tee %' <<< '.claude/settings.` + L + `'`),
		sh(`source <(echo tee '.claude/settings.` + L + `')`),
		sh(`eval tee 'dlink/settings.` + L + `'`),
		sh(`eval tee 'lnk/../settings.` + L + `'`),
		sh(`eval tee '.{claude,{1..70}}/settings.json'`),
		sh(`eval "eval \"tee .claude/settings.` + L + `\""`),
		sh(`eval tee '.cl\aude/settings.` + L + `'`),
		sh(`eval tee '.cl"au"de/settings.` + L + `'`),
		// Fable r4 2.
		sh(`tee {a}b,.clau\de/'set'}{t\ings.json,{a,b},''}`),
		// Fable r4 4: an inner brace group without a comma.
		sh(`tee .claude/settings.{x}y,json}`),
		sh(`tee {a}b,.claude/settings.jso}n`),
		sh(`tee .claude{},/settings.json}`),
		sh(`tee {x}y,dlink}/settings.json`),
		sh(`tee {a}b,{},dlink/settings.j}son`),
		sh(`tee '.claude'{},'}',/settings.json}`),
		sh(`sed -i s/a/b/ .claude/settings.{x}y,json}`),
		sh(`rm .claude/settings.{x}y,json}`),
		sh(`touch .claude/settings.{x}y,json}`),
		sh(`cp /etc/hosts .claude/settings.{x}y,json}`),
		sh(`tee .claude/settings.{x}y,json,{1..70}}`),
		sh(`tee .claude/{x}y,settings.json}`),
		// Fable r4 5: -C glued to a link.
		sh(`env -Cdlink tee settings.json`),
		sh(`env -Cdlink sh -c 'echo x > settings.json'`),
		sh(`env -iCdlink tee settings.json`),
		// Fable r4 6: chained directory changes.
		sh(`env -C .claude env -C sub tee ../settings.json`),
		sh(`env -C free env -C ../lnk tee ../settings.json`),
		sh(`CDPATH=.claude cd sub; tee ../settings.json`),
		// Fable r4 7: a stream opened on the file for input.
		sh(`bash -c 'echo x > /dev/stderr' 2<.claude/settings.json`),
		sh(`sh -c 'echo x > /dev/stdout' 1<.claude/settings.json`),
		// Fable r4 8: a second quoting level under eval.
		sh(`eval tee .cl\\aude/settings.json`),
		sh(`eval tee \"dlink/settings.json\"`),
		sh(`eval tee .cl\\aude/settings.` + L),
		// Fable r4 9 and the zsh form.
		sh(`fish -c 'echo x >? .claude/settings.json'`),
		sh(`zsh -c 'echo x >! .claude/settings.json'`),
		sh(`bash -c 'echo x >| .claude/settings.json'`),
		{name: "apply_patch cwd / etc/passwd", pol: filepath.Join("..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_writes.yaml"),
			ev: toolEv("apply_patch", "/", map[string]interface{}{"patch": review090cPatch("etc/passwd")})},
		// Gemini r4 1.
		sh(`eval python3 w.py '.claude/settings.` + L + `'`),
		sh(`eval python3 w.py .claude/settings.'` + L + `'`),
		sh(`eval python3 w.py .claude/settings.\{json,\{1..70\}\}`),
		sh(`eval python3 w.py '.{claude,{1..70}}/settings.json'`),
		named("eval 8200 a then long list", sh(`eval 'echo `+strings.Repeat("a", 8200)+`; python3 w.py .claude/settings.`+L+`'`)),
		named("trap 8200 a then long list", sh(`trap 'echo `+strings.Repeat("a", 8200)+`; python3 w.py .claude/settings.`+L+`' EXIT`)),
		sh(`eval 'cd lnk; python3 w.py ../settings.` + L + `'`),
		sh(`eval 'env -C lnk python3 w.py ../settings.` + L + `'`),
		sh(`eval "eval 'python3 w.py .{claude,{1..70}}/settings.json'"`),
		// Gemini r4 2: an fd moved onto the output.
		sh(`X=.cl; Y=aude/settings.json; exec < $X$Y; exec 1>&0-; echo x > /dev/stdout`),
		sh(`X=.cl; Y=aude/settings.json; echo x < $X$Y 1>&0- > /dev/stdout`),
		sh(`X=.cl; Y=aude/settings.json; echo x < $X$Y 2>&0- > /dev/stderr`),
		sh(`echo x 1>&0- > .claude/settings.json`),
		sh(`echo x < .claude/settings.json 1>&0- > /dev/stdout`),
		// Gemini r4 3: unread directory changes.
		sh(`D=lnk; cd $D; python3 w.py ./../settings.` + L),
		sh(`D=lnk; env -C $D python3 w.py ./../settings.` + L),
		sh(`D=lnk; cd -P $D; python3 w.py ../settings.` + L),
		sh(`D=lnk; cd -- $D; python3 w.py ../settings.` + L),
		sh(`D=lnk; env -iC"$D" python3 w.py ../settings.` + L),
		sh(`D=lnk; env --ch="$D" python3 w.py ../settings.` + L),
		sh(`env -C"$D" python3 w.py ../settings.json`),
		sh(`cd $D; echo x > ../settings.json`),
		sh(`D=ln; D+=k; cd $D; python3 w.py ../settings.json`),
		// Gemini r4 4: ~ and glued options through links into /proc or
		// /dev/fd.
		shIn("/tmp", `exec 3< `+cdir+` && echo x > ~/pl3/settings.json`),
		shIn(cdir, `echo x > ~/pl/settings.json`),
		shIn("/tmp", `exec 3< `+cdir+` && fish -o ~/pl3/settings.json -c true`),
		shIn("/tmp", `exec 3< `+cdir+` && cp /etc/hosts ~/pl3/settings.json`),
		sh(`exec 3< ` + cdir + ` && dd if=/etc/hosts of=pl3/settings.json`),
		sh(`exec 3< ` + cdir + ` && dd if=/etc/hosts of=` + home + `/pl3/settings.json`),
		sh(`exec 3< ` + cdir + ` && tar -cfpl3/settings.json /etc/hosts`),
		// Gemini r4 5: a backslash-newline pair.
		sh("python3 w.py .cl\\\naude/settings." + L),
		sh("python3 w.py \".cl\\\naude/settings.\"" + L),
		// Gemini r4 6.
		{name: "apply_patch 18 levels with escaped markers", raw: deepRaw},
		// Gemini r4 7: many directories before a directory change.
		named("35 dirs then env -C lnk ..", sh("ls "+dirs35+"; env -C lnk python3 w.py ../settings.json")),
		named("35 dirs then env -Clnk ..", sh("ls "+dirs35+"; env -Clnk python3 w.py ../settings.json")),
		// Gemini r4 8: a glued -o option.
		sh(`zsh -oerrexit -c 'echo x > $X'`),
		sh(`zsh +oerrexit -c 'echo x > $X'`),
		// Gemini r4 9: long option clusters.
		named("tar -c 35 v f settings.json", shIn(cdir, "tar -c"+strings.Repeat("v", 35)+"fsettings.json /etc/hosts")),
		named("env -18 i Clnk ../settings.json", sh("env -"+strings.Repeat("i", 18)+"Clnk python3 w.py ../settings.json")),
		named("env -18 i Clnk long list", sh("env -"+strings.Repeat("i", 18)+"Clnk python3 w.py ../settings."+L)),
		// B1, B1b, B1c, B2: an unread directory with commands that only read.
		sh(`cd $(printf .cl)aude && echo pwn > settings.json`),
		sh(`cd .cl* && echo pwn > settings.json`),
		named("B1c padding then cd .claude", sh("echo "+strings.Repeat("a/b ", 100000)+"; cd .claude && echo pwn > settings.json")),
		sh(`cd $(printf .cl)aude && echo pwn 2< settings.json > /dev/stderr`),
		// B3, B4, B5: a redirect after a directory change, CDPATH set by
		// printf, find -execdir.
		sh(`D=ln; D+=k; cd < /tmp "$D" && tee ../settings.json <<< pwn`),
		sh(`D=.cl; D+=aude; HOME="$D" cd < /tmp && tee settings.json <<< pwn`),
		sh(`D=ln; D+=k; env -C < /tmp "$D" tee ../settings.json <<< pwn`),
		sh(`X=.cl; X+=aude; printf -v CDPATH %s "$X"; cd sub; tee ../settings.json <<< pwn`),
		sh(`find . -maxdepth 2 -name '*.json' -execdir tee settings.json \; <<< pwn`),
		// B6, B7: escapes split by quotes, a NUL in $'...'.
		{name: "B6 eval with split hex escapes", ev: bashEv(b6, home)},
		sh(`python3 w.py $'.claude/settings.json\x00foo'`),
		sh(`eval $'tee .claude/settings.json\x00foo' <<< pwn`),
		// B8: a path with a space.
		sh(`python3 w.py 'my link/settings.json'`),
		// B9, B15: literal braces, an escaped comma, / inside a list.
		sh(`python3 w.py {x}/settings.json`),
		sh(`python3 w.py {a\,b,c}/settings.json`),
		sh(`python3 w.py .cl{aude/settings,foo}.json`),
		// B10, B14: a glob or a list as the first part; @, + and %.
		sh(`python3 w.py dlin*/settings.json`),
		sh(`python3 w.py {dlink,{1..70}}/settings.json`),
		{name: "B10 new protected file in its directory", ev: bashEv(`python3 w.py new.json`, cdir), protect: []string{filepath.Join(cdir, "new.json")}},
		sh(`python3 w.py @dlink/settings.json`),
		sh(`python3 w.py a+.claude/settings.json`),
		sh(`python3 w.py a%.claude/settings.json`),
		// B11: a protected directory.
		{name: "B11a cd $D then protect-paths", ev: bashEv(`D=.tool-; D+=guard; cd "$D"; python3 ~/w.py protect-paths`, home), protect: tgOnly},
		{name: "B11b ~/pl/protect-paths", ev: bashEv(`python3 ~/w.py ~/pl/protect-paths`, tg), protect: tgOnly},
		{name: "B11c cp to ~/pl/protect-paths", ev: bashEv(`cp /etc/hosts ~/pl/protect-paths`, tg), protect: tgOnly},
		// B12: a link to the file after an unread cd; cp -r into ..
		sh(`D=fr; D+=ee; cd "$D"; echo pwn > alias`),
		sh(`D=ln; D+=k; cd "$D"; cp -r ` + evil + `/. ..`),
		// B13: a path made only of variables.
		sh(`A=.cl; B=aude; C=settings; D=.json; tee "$A$B/$C$D" <<< pwn`),
		// B16: a glued -o cluster.
		sh(`X=.claude/settings.json bash -oe pipefail -c 'rm$IFS$X'`),
		// The four round-4 probes.
		sh(`eval tee ".claude/settings.json$(printf '\x2c%s' {1..70})"`),
		// Found in this round: a backslash, a quote and a newline join the
		// name once eval reads the text again.
		sh("eval 'tee .cl\\'\"\n\"'aude/settings.json'"),
		sh("eval 'tee .cl\\'\"\n\"'aude/settings.js'on"),
		sh("eval \"tee .cl\\\\\"'\n'\"aude/settings.json\""),
		sh(`eval 'tee .cl\'$'\n''aude/settings.json'`),
		sh("bash -c 'tee .cl\\'\"\n\"'aude/settings.json'"),
		// Round 8: a group with no comma inside a list item, and sequences
		// longer than 64 characters.
		sh(`tee .claude/setting{s,{x}}.jso{n..n..1}`),
		sh(`tee .claude/setting{s,x{y}z}.jso{n..n..01}`),
		sh(`tee {.,{x}}claude/setting{s,{y}}.jso{n..n..1}`),
		sh(`tee dlink/setting{s,{x}}.js{q..o..1}n`),
		sh(`echo x > .claude/setting{s,{x}}.jso{n..n..01}`),
		sh("tee .claud{e..e.." + z62 + "1}/settings.{json,{1..70}}"),
		sh("tee .claud{e..e.." + z62 + "1}/settings.json"),
		sh("tee .claude/settings.js{o..o.." + z62 + "1}n"),
		sh("eval $'tee\\t.claud{e..e.." + z62 + "1}/settings.json'"),
		sh("eval $'tee\\t.claude/settings.jso{n..n.." + z62 + "1}'"),
	}
	// B8b: a protected path with a space in it, read by its absolute path.
	spaced := filepath.Join(t.TempDir(), "my home")
	spacedFile := filepath.Join(spaced, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(spacedFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spacedFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, review090eCase{name: "B8b absolute path with a space", ev: bashEv(`python3 w.py '`+spacedFile+`'`, "/tmp"), protect: []string{spacedFile}})
	review090eEach(t, home, file, cases, func(t *testing.T, got, reason string, took time.Duration) {
		if got != "deny" {
			t.Errorf("decision %q (%s), want deny", got, reason)
		}
		if took > 2*time.Second {
			t.Errorf("took %s, want under 2s", took)
		}
	})
}

// Sixth-round cases: every probe of the round-5 reviews (Fable 1-5,
// Gemini 1-6) that must be denied. d5 and s42 are links to the protected
// directory whose names a long sequence makes.
func TestReview090eRound5Probes(t *testing.T) {
	home, cdir, _, _, _, _ := review090eTree(t)
	file := filepath.Join(cdir, "settings.json")
	for _, name := range []string{"d5", "s42"} {
		if err := os.Symlink(cdir, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	sh := func(cmd string) review090eCase { return review090eCase{name: cmd, ev: bashEv(cmd, home)} }
	shIn := func(cwd, cmd string) review090eCase {
		return review090eCase{name: cmd + " (cwd " + filepath.Base(cwd) + ")", ev: bashEv(cmd, cwd)}
	}
	cases := []review090eCase{
		// Fable r5 1: separators that only the decoded $'...' text has.
		sh(`eval $'tee\t.claude/settings.{json,{1..70}}'`),
		sh(`eval $'tee\x20.claude/settings.{json,{1..70}}'`),
		sh(`eval $'tee\n.claude/settings.{json,{1..70}}'`),
		sh(`eval $'tee\t.{claude,{1..70}}/settings.json'`),
		sh(`eval $'python3 w.py\t.claude/settings.{json,{1..70}}'`),
		sh(`eval $'tee\t.claude/settings.json'`),
		sh(`eval $'cd\t.claude\ntee\tsettings.json'`),
		sh(`trap $'tee\t.claude/settings.json' EXIT`),
		// Fable r5 2 and Gemini r5 1: sequences of netMaxList words and
		// more, at 4095, 4096, 4097 and 5000.
		sh(`tee d{1..5000}/settings.json`),
		sh(`sed -i s/a/b/ d{1..5000}/settings.json`),
		sh(`rm -f d{1..5000}/settings.json`),
		sh(`touch d{1..5000}/settings.json`),
		sh(`cp /etc/hosts d{5..5000}/settings.json`),
		sh(`python3 w.py d{1..4097}/settings.json`),
		sh(`python3 w.py d{{1..5000},x}/settings.json`),
		sh(`python3 w.py d{1..4096}/settings.json`),
		sh(`python3 w.py d{1..4095}/settings.json`),
		sh(`tee d{1..4096}/settings.json`),
		sh(`tee d{1..4097}/settings.json`),
		sh(`echo pwn > d{1..4096}/settings.json`),
		sh(`echo pwn > d{1..4097}/settings.json`),
		sh(`echo pwn > d{0..5000}/settings.json`),
		shIn(cdir, `tee /proc/{1..5000}/cwd/settings.json <<< PWNED`),
		sh(`tee s{0..5000}/settings.json <<< pwn`),
		sh(`python3 w.py /proc/{1..5000}/cwd/settings.json`),
		sh(`python3 w.py /proc/{1..5000}/fd/3/settings.json`),
		sh(`echo pwn > s{0..5000}/settings.json`),
		sh(`python3 w.py s{0..5000}/settings.json`),
		sh(`python3 w.py s{5000..1..-1}/settings.json`),
		sh(`python3 w.py s{0001..5000}/settings.json`),
		sh(`fish -o s{0..5000}/settings.json -c true`),
		// Fable r5 4: a redirect after a directory change of the shell
		// that opens it.
		sh(`cd "$DIR" && make > build.log`),
		sh(`cd "$(dirname "$0")" && ./run.sh > out.log`),
		sh(`cd "$D" && (echo x > alias)`),
		sh(`(cd "$D"; echo x > alias)`),
		sh(`(cd "$D" && (echo x > alias))`),
		sh(`pushd "$D"; echo x > alias`),
		sh(`popd; echo x > alias`),
		sh(`CDPATH=/x cd d5 && echo x > settings.json`),
		sh(`cd "$D" && echo x > alias`),
		sh(`env -C "$D" sh -c 'echo x > alias'`),
		sh(`git -C "$D" log; bash -c 'echo x > alias'`),
		sh(`cd "$D" && bash -c 'echo x > alias'`),
		sh(`cd dl?nk && echo x > settings.json`),
		sh(`cd zz* && echo x > alias`),
		sh(`git -C "$R" log > settings.json`),
		sh(`cd "$D" && make > alias`),
		sh(`cd "$D"; (make) > alias`),
		sh(`cd "$D" && { make; } > alias`),
		sh(`cd ${D} > x; echo x > alias`),
		sh(`sh -c 'cd "$1" && echo x > alias' _ d`),
		// Fable r5 5: substitutions and escaped blanks in text read again.
		sh(`eval 'tee .cl$(true)aude/settings.json'`),
		sh(`eval 'tee $(echo .claude)/settings.json'`),
		sh(`eval 'echo x > .cl$(true)aude/settings.json'`),
		sh(`trap 'tee .cl$(true)aude/settings.json' EXIT`),
		sh("eval 'tee .cl`true`aude/settings.json'"),
		sh(`eval 'tee my\ link/settings.json'`),
		sh(`eval "tee my\\ link/settings.json"`),
		sh(`eval 'python3 w.py my\ link/settings.json'`),
		// Fable r5 5: directory changes the indicator list did not know.
		sh(`D=dl; D+=ink; C=cd; $C "$D"; tee settings.json`),
		sh(`go -C "$D" run . ; tee settings.json`),
		sh(`cargo -C "$D" build; tee settings.json`),
		sh(`pnpm -C "$D" i; tee settings.json`),
		sh(`sudo -D "$D" true; tee settings.json`),
		sh(`nsenter --wd="$D" true; tee settings.json`),
		sh(`chroot "$D" true; tee settings.json`),
		sh(`bsdtar --cd "$D" -xf a.tar; tee settings.json`),
		sh(`docker run -w "$D" img; tee settings.json`),
		sh(`sudo -D "$D" tee settings.json`),
		sh(`nsenter --wd="$D" tee settings.json`),
		sh(`docker run -w "$D" img tee settings.json`),
		// Fable r5 5: collating elements and classes in a bracket.
		sh(`python3 w.py dlin[[.k.]]/settings.json`),
		sh(`python3 w.py dlin[[=k=]]/settings.json`),
		sh(`python3 w.py dlin[[:alpha:]]/settings.json`),
		// Gemini r5 3 and 4: a stream opened on the file for input.
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<$'.claude/settings.json\x00foo'`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<$'.claude/settings.json'`),
		sh(`sh -c 'echo PWNED > /dev/stdout' 1<$'.claude/settings.json'`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<$'dlink/settings.json'`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<dlink/$'\x73ettings.json'`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<.claude/$'settings.json'`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<$".claude/settings.json"`),
		sh(`bash -c 'echo PWNED > /dev/stderr' 2<$"."claude/settings.json`),
		sh(`echo PWNED < .claude/settings.json 1>&0- > /de'v'/stdout`),
		sh(`echo PWNED < dlink/settings.json 1>&0- > /de'v'/stdout`),
		sh(`echo PWNED < .claude/settings.json 1>&0- > /de\v/stdout`),
		sh(`echo PWNED < .claude/settings.json 1>&0- > /pr'o'c/self/fd/1`),
		sh(`echo PWNED < .claude/settings.json 1>&0- > /de'v'/fd/1`),
		sh(`bash -c 'echo PWNED > /de"v"/stderr' 2<.claude/settings.json`),
		sh(`bash -c 'echo PWNED > /d\ev/stderr' 2<.claude/settings.json`),
		sh(`sh -c 'echo PWNED > /de"v"/stdout' 1<.claude/settings.json`),
		sh(`bash -c 'echo PWNED > /pr"o"c/self/fd/2' 2<.claude/settings.json`),
		// Gemini r5 5: directory changes and HOME set in decoded text.
		sh(`D=ln; D+=k; eval $'c\x64 "$D"; tee ../settings.json <<< PWNED'`),
		sh(`D=ln; D+=k; eval $'env -\x43 "$D" tee ../settings.json <<< PWNED'`),
		sh(`X=.cl; X+=aude; printf -v $'CD\x50ATH' %s "$X"; cd sub; tee ../settings.json <<< PWNED`),
		sh(`X=.cl; X+=aude; printf -v HOME %s "$X"; cd; tee settings.json <<< PWNED`),
		sh(`X=.cl; X+=aude; read HOME <<< "$X"; cd; tee settings.json <<< PWNED`),
		sh(`X=` + cdir + `; printf -v HOME %s "$X"; tee ~/settings.json <<< PWNED`),
		sh(`X=` + cdir + `; printf -v HOME %s "$X"; echo x > ~/settings.json`),
		// Gemini r5 6: eval text and shells that read standard input.
		sh(`D=fr; D+=ee; eval 'cd "$D"; echo PWNED > alias'`),
		sh(`export D=fr; D+=ee; echo 'cd "$D"; echo PWNED > alias' | sh`),
		sh(`A=.cl; B=aude; C=settings; D=.json; eval 'tee "$A$B/$C$D" <<< PWNED'`),
		sh(`A=.cl; B=aude; C=settings; D=.json; eval 'echo PWNED > "$A$B/$C$D"'`),
		sh(`bash <<< 'echo PWNED > "$A$B/$C$D"'`),
	}
	review090eEach(t, home, file, cases, func(t *testing.T, got, reason string, took time.Duration) {
		if got != "deny" {
			t.Errorf("decision %q (%s), want deny", got, reason)
		}
		if took > 2*time.Second {
			t.Errorf("took %s, want under 2s", took)
		}
	})
}

func TestReview090eOrdinaryCommands(t *testing.T) {
	home, _, file, _, _, _ := review090eTree(t)
	sh := func(cmd string) review090eCase { return review090eCase{name: cmd, ev: bashEv(cmd, home)} }
	dispatch := []string{"-dispatch", "gh_read"}
	cases := []review090eCase{
		sh(`bash -c 'ls'`),
		sh(`make 2>/dev/stderr`),
		sh(`git -C repo status`),
		sh(`cat f > /dev/stdout`),
		sh(`python3 -c 'print({"a":1})'`),
		sh(`python3 -c 'print({"a":1,"b":{"c":2}})'`),
		sh(`touch a{1,2}.txt`),
		sh(`echo hi`),
		sh(`rg -C 3 foo`),
		sh(`git diff -C`),
		sh(`jq '.a >= 0' f`),
		sh(`grep '<tag>' f`),
		sh(`cmd 2>&-`),
		sh(`cd build && cmake .. && make -j8`),
		// Fable r5 4: ordinary programs and redirects after a directory
		// change of one program or of a ( ) group that has ended.
		sh(`awk '{s+=$2} END{print s}' f`),
		sh(`awk '{a[$1]++} END{for(k in a) print k}' f`),
		sh(`kubectl get pods -o jsonpath='{.items[0].metadata.name}'`),
		sh(`(cd "$DIR" && make) > build.log`),
		sh(`(cd "$D"); make > log.txt`),
		sh(`git -C "$R" log > log.txt`),
		sh(`git -C "$R" log > out.txt 2>&1`),
		sh(`make -C "$D" > log.txt`),
		sh(`env -C "$D" make > log.txt`),
		sh(`echo hi | bash`),
		sh(`echo 'ls -l' | bash`),
		sh(`eval 'echo hi'`),
		sh(`trap 'echo bye' EXIT`),
		// Fable r5 3 and Gemini r5 2: sequences at the int64 limits.
		sh(`echo {-9223372036854775808..9223372036854775807}`),
		sh(`ls {-9223372036854775808..9223372036854775807}`),
		sh(`echo {9223372036854775807..9223372036854775807}`),
		sh(`echo {0..-9223372036854775808}`),
		sh(`echo {a..z..-9223372036854775808}`),
		sh(`echo {1..-9223372036854775807}`),
		sh(`echo {9223372036854775806..9223372036854775807..2}`),
		{name: "apply_patch in a normal tree", ev: toolEv("apply_patch", filepath.Join(home, "free"), map[string]interface{}{"patch": review090cPatch("notes.txt")})},
		{name: "dispatch Glob", ev: toolEv("Glob", home, map[string]interface{}{"pattern": "**/*.go"}), extra: dispatch},
		{name: "dispatch Grep", ev: toolEv("Grep", home, map[string]interface{}{"pattern": "foo", "path": home}), extra: dispatch},
		{name: "dispatch Task", ev: toolEv("Task", home, map[string]interface{}{"prompt": "list the files", "description": "x"}), extra: dispatch},
		{name: "dispatch MCP", ev: toolEv("mcp__docs__search", home, map[string]interface{}{"query": "settings"}), extra: dispatch},
	}
	review090eEach(t, home, file, cases, func(t *testing.T, got, reason string, took time.Duration) {
		if got == "deny" {
			t.Errorf("decision deny (%s), want not deny", reason)
		}
		if took > 2*time.Second {
			t.Errorf("took %s, want under 2s", took)
		}
	})
	floorDenies := []review090eCase{
		// main denies this; the frozen floor keeps main's verdict.
		sh(`echo '{"a":[1,2],"b":{"c":"d"}}' > out.json`),
		// main denies this; the frozen floor keeps main's verdict.
		sh(`curl -d '{"items":[1,2],"meta":{"k":"v"}}' http://x/y`),
		// main denies this; the frozen floor keeps main's verdict.
		sh(`touch file{1..100}.txt`),
	}
	review090eEach(t, home, file, floorDenies, func(t *testing.T, got, reason string, took time.Duration) {
		if got != "deny" {
			t.Errorf("decision %q (%s), want deny", got, reason)
		}
		if took > 2*time.Second {
			t.Errorf("took %s, want under 2s", took)
		}
	})
}

// Pathological inputs from both round-4 reviews and the attack review of
// the design: each ends in under 2 s and is not denied on the time limit.
func TestReview090ePathologicalInputs(t *testing.T) {
	home, _, file, _, _, _ := review090eTree(t)
	// A directory with many entries, as /tmp was in the Fable review.
	big := t.TempDir()
	for i := 0; i < 1200; i++ {
		if err := os.WriteFile(filepath.Join(big, "e"+itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"a", "b", "c", "d", "e"} {
		if err := os.MkdirAll(filepath.Join(big, "node_modules", d+"x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nested := func(depth int) string { return strings.Repeat("{", depth) + "a,b" + strings.Repeat("}", depth) }
	args := func(n int, w string) string { return strings.TrimSpace(strings.Repeat(w+" ", n)) }
	commas := "{" + strings.TrimSuffix(strings.Repeat("a,", 50000), ",") + "}"
	inner := `bash -c "echo a; echo b" "x y" "z w"`
	branch := inner
	for i := 0; i < 4; i++ {
		q := strings.ReplaceAll(branch, `"`, `\"`)
		branch = `bash -c "` + q + `" "` + q + `"`
	}
	cmds := []struct{ name, cmd, cwd string }{
		// Fable r4 9: lists in a large directory.
		{"ls node_modules list", "ls node_modules/{.cache,{a..z}*}", big},
		{"rm -rf node_modules list", "rm -rf node_modules/{.cache,{a..z}*}", big},
		{"ls {a..e}*", "ls {a..e}*", big},
		// Gemini r4 10: deep single-item lists.
		{"redirect 80000 nested", "echo x > ''" + nested(80000), home},
		{"redirect 60000 nested", "echo x > ''" + nested(60000), home},
		{"10 args of 4000 nested", "python3 w.py " + args(10, nested(4000)), home},
		{"5 args of 4000 nested", "python3 w.py " + args(5, nested(4000)), home},
		// Attack section 3.
		{"- then 200000 a", "python3 w.py -" + strings.Repeat("a", 200000), home},
		{"100000 a=", "python3 w.py " + strings.Repeat("a=", 100000), home},
		{"50000 commas in a large directory", "rm " + commas, big},
		{"branching bash -c", branch, home},
		{"1000 directory names", "ls " + strings.Repeat("node_modules ", 1000) + "; tee " + strings.Repeat("x/y ", 2000), big},
	}
	var cases []review090eCase
	for _, c := range cmds {
		cases = append(cases, review090eCase{name: c.name, ev: bashEv(c.cmd, c.cwd)})
	}
	// The floor, the check of 22ed838, runs on every call the new check
	// allows, and it spends most of the time on "10 args of 4000 nested":
	// 1.43 s of 1.83 s in a race build on 2 cores, 0.54 s without -race. CI
	// took 3.73 s and 3.99 s on that case. "5 args of 4000 nested" took
	// 2.15 s and 3.10 s in a race build on 2 cores of a loaded machine. So
	// these two cases have 5 s, and every other case 2 s.
	limits := map[string]time.Duration{
		"10_args_of_4000_nested": 5 * time.Second,
		"5_args_of_4000_nested":  5 * time.Second,
	}
	review090eEach(t, home, file, cases, func(t *testing.T, got, reason string, took time.Duration) {
		limit := 2 * time.Second
		for name, l := range limits {
			if strings.Contains(t.Name(), "/"+name+"/") {
				limit = l
			}
		}
		if took > limit {
			t.Errorf("took %s, want under %s", took, limit)
		}
		if strings.Contains(reason, "did not end in") {
			t.Errorf("denied on the time limit: %s", reason)
		}
		if got != "" && got != "allow" && got != "deny" && got != "ask" {
			t.Errorf("decision %q", got)
		}
	})
}
