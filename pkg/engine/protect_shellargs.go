package engine

import (
	"path/filepath"
	"strings"
)

// shellCall is what a shell does with its arguments, as parseShellCall reads
// them.
type shellCall struct {
	// known is false when a word in the option list is not resolved
	// (bash $OPTS 'cmd') or names an option this parser does not know.
	// Then the words after it may be commands of any kind.
	known bool
	// commands are the texts the shell runs: the text of -c and the value
	// of a command option (fish -C, --init-command). When known is false,
	// every word from the unknown one on is a command too.
	commands []shellToken
	// dashC: the call has -c (or fish --command).
	dashC bool
	// stdin: the shell reads its commands from the standard input (-s, or
	// no -c and no script operand).
	stdin bool
	// runsInput: an option makes the shell read commands of its own
	// beyond the -c text: -i, -s, --rcfile, --init-file.
	runsInput bool
	// plain: every option only changes how the shell runs its commands
	// (-e, -x, --norc). An option that reads a startup file, sets a named
	// option, or writes a file clears it.
	plain bool
	// files are values of options that make the shell write a file
	// (fish -o, --debug-output, -p, --profile, --profile-startup).
	files []shellToken
	// positionals are the words after the text of -c, other than the
	// empty word. The shell does not run them, but the text can
	// (bash -c 'eval "$1"' _ 'rm f'), so the write check reads each one as
	// a command too. The read-only rule does not need them to read only.
	positionals []shellToken
}

// writeCheckTexts returns the texts the write check reads as commands: the
// commands of the call and its positional parameters.
func (c shellCall) writeCheckTexts() []shellToken {
	return append(append([]shellToken(nil), c.commands...), c.positionals...)
}

// plainShellLetters are the short options of a POSIX shell that only change
// how it runs its commands: errexit, xtrace, nounset, verbose, noexec,
// noglob, allexport, notify, hashall, keyword, privileged, onecmd,
// noclobber, braceexpand, histexpand, physical, errtrace and functrace.
const plainShellLetters = "exuvnfabhkptCBHPET"

// plainShellLongOptions are the long options of bash that only change how
// it runs its commands.
var plainShellLongOptions = map[string]bool{
	"--norc": true, "--noprofile": true, "--verbose": true, "--noediting": true,
}

// parseShellCall reads the arguments of a shell call: args are the words
// after the program name. fish has an option list of its own; every other
// shell in shellInterpreters is read as a POSIX shell.
func parseShellCall(prog string, args []shellToken) shellCall {
	if filepath.Base(prog) == "fish" {
		return parseFishCall(args)
	}
	return parsePOSIXShellCall(args)
}

// unresolvedLongOption returns the name of a word --NAME=VALUE whose value
// holds an expansion: the name stands before the first expansion. ok is
// false for any other unresolved word.
func unresolvedLongOption(w shellToken) (string, bool) {
	head := w.marked
	if k := strings.IndexByte(head, shellUnresolvedMark); k >= 0 {
		head = head[:k]
	}
	eq := strings.IndexByte(head, '=')
	if !strings.HasPrefix(head, "--") || eq < 3 {
		return "", false
	}
	return head[2:eq], true
}

// unknownShellRest marks a call whose option list cannot be read from word
// i on: every word from there on may be a command text (bash -c "$CMD",
// bash $OPTS 'rm f').
func unknownShellRest(c shellCall, args []shellToken, i int) shellCall {
	c.known, c.plain = false, false
	for ; i < len(args); i++ {
		if args[i].unresolved || args[i].value != "" {
			c.commands = append(c.commands, args[i])
		}
	}
	return c
}

// parsePOSIXShellCall reads the arguments of bash, sh, zsh, dash, ksh and
// the like. The options run up to the first word that is not an option, or
// up to "--" or "-". In a cluster, c asks for a command text, s for the
// standard input, i for an interactive shell, and each o or O takes the next
// word as an option name. With -c the first word after the options is the
// command text, and every later word is a positional parameter, which the
// shell does not run. Without -c that word is a script file.
func parsePOSIXShellCall(args []shellToken) shellCall {
	c := shellCall{known: true, plain: true}
	i := 0
	for i < len(args) {
		w := args[i]
		v := w.value
		if w.unresolved {
			if _, ok := unresolvedLongOption(w); !ok {
				return unknownShellRest(c, args, i)
			}
			// --NAME=$VALUE: a long option whose value is not known
			// (bash --rcfile="$HOME/.bashrc"). bash reads --rcfile and
			// --init-file only with the file in the next word.
			c.plain = false
			i++
			continue
		}
		if v == "--" || v == "-" {
			i++
			break
		}
		if len(v) < 2 || (v[0] != '-' && v[0] != '+') {
			break
		}
		i++
		if strings.HasPrefix(v, "--") {
			switch {
			case v == "--rcfile" || v == "--init-file":
				c.runsInput, c.plain = true, false
				i++ // the file name
			case !plainShellLongOptions[v]:
				c.plain = false
			}
			continue
		}
		names := 0
		for _, ch := range v[1:] {
			switch {
			case ch == 'c':
				c.dashC = true
			case ch == 'o' || ch == 'O':
				names++
				c.plain = false
			case ch == 's' || ch == 'i':
				c.runsInput, c.plain = true, false
				if ch == 's' {
					c.stdin = true
				}
			case strings.ContainsRune(plainShellLetters, ch):
			default:
				c.plain = false
			}
		}
		i += names
	}
	if i > len(args) {
		i = len(args)
	}
	switch {
	case c.dashC && i < len(args):
		c.commands = append(c.commands, args[i])
		c.positionals = nonEmptyWords(args[i+1:])
	case !c.dashC && i >= len(args):
		c.stdin = true
	}
	return c
}

// nonEmptyWords returns the words that are not the empty word "".
func nonEmptyWords(words []shellToken) []shellToken {
	var out []shellToken
	for _, w := range words {
		if w.unresolved || w.value != "" {
			out = append(out, w)
		}
	}
	return out
}

// fishValueLetters are the short options of fish that take a value: the
// value is the rest of the word (-C'cmd') or the next word.
const fishValueLetters = "cCpdofD"

// fishFlagLetters are the short options of fish that take no value.
const fishFlagLetters = "hPilNnv"

// fishLongOptions are the long options of fish, each with the short letter
// it stands for ('3' for --profile-startup, '1' for the options that only
// print) and whether it takes a value.
var fishLongOptions = []struct {
	name   string
	letter byte
	value  bool
}{
	{"command", 'c', true}, {"init-command", 'C', true}, {"features", 'f', true},
	{"debug", 'd', true}, {"debug-output", 'o', true}, {"debug-stack-frames", 'D', true},
	{"interactive", 'i', false}, {"login", 'l', false}, {"no-config", 'N', false},
	{"no-execute", 'n', false}, {"print-rusage-self", '1', false},
	{"print-debug-categories", '1', false}, {"profile", 'p', true},
	{"profile-startup", '3', true}, {"private", 'P', false}, {"help", 'h', false},
	{"version", 'v', false},
}

// fishLongOption finds a long option of fish by its name or by a prefix of
// one, as getopt_long does. A prefix that fits more than one option is an
// error for fish; it is read here as the command option when one of the
// options it fits carries a command (--i fits --interactive and
// --init-command), so the value is checked as a command. ok is false for a
// name that fits no option, or only options that carry no command.
func fishLongOption(name string) (letter byte, value, ok bool) {
	var hits []int
	for k, o := range fishLongOptions {
		if o.name == name {
			return o.letter, o.value, true
		}
		if strings.HasPrefix(o.name, name) {
			hits = append(hits, k)
		}
	}
	if len(hits) == 1 {
		o := fishLongOptions[hits[0]]
		return o.letter, o.value, true
	}
	for _, k := range hits {
		if l := fishLongOptions[k].letter; l == 'c' || l == 'C' {
			return 'C', true, true
		}
	}
	return 0, false, false
}

// parseFishCall reads the arguments of fish. fish reads its options with
// getopt "+hPilNnvc:C:p:d:o:f:D:" and the long options in fishLongOptions,
// so the options run up to the first word that is not an option or "--",
// also after the value of -c (fish -c CMD -C CM runs CM too). Each -c and
// each -C gives a command. With -c the words after the options are
// positional parameters; without it the first is a script file.
func parseFishCall(args []shellToken) shellCall {
	c := shellCall{known: true, plain: true}
	apply := func(letter byte, val shellToken, have bool) {
		switch letter {
		case 'c', 'C':
			if letter == 'c' {
				c.dashC = true
			}
			if have {
				c.commands = append(c.commands, val)
			}
		case 'o', 'p', '3':
			c.plain = false
			if have {
				c.files = append(c.files, val)
			}
		case 'i', 'l':
			c.runsInput, c.plain = true, false
		}
	}
	i := 0
	for i < len(args) {
		w := args[i]
		v := w.value
		if w.unresolved {
			name, ok := unresolvedLongOption(w)
			if !ok {
				return unknownShellRest(c, args, i)
			}
			letter, takes, ok := fishLongOption(name)
			if !ok || !takes {
				return unknownShellRest(c, args, i)
			}
			val := markedAfterEq(w)
			apply(letter, shellToken{kind: tokWord, value: val, raw: val, marked: val, unresolved: true}, true)
			i++
			continue
		}
		if v == "--" {
			i++
			break
		}
		if len(v) < 2 || v[0] != '-' {
			break
		}
		i++
		if strings.HasPrefix(v, "--") {
			name, hasEq := v[2:], false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name, hasEq = name[:eq], true
			}
			letter, takes, ok := fishLongOption(name)
			if !ok {
				return unknownShellRest(c, args, i)
			}
			switch {
			case takes && hasEq:
				val := v[strings.IndexByte(v, '=')+1:]
				apply(letter, shellToken{kind: tokWord, value: val, raw: val, marked: markedAfterEq(w), unresolved: w.unresolved}, true)
			case takes && i < len(args):
				apply(letter, args[i], true)
				i++
			default:
				apply(letter, shellToken{}, false)
			}
			continue
		}
		for k := 1; k < len(v); k++ {
			ch := v[k]
			if strings.IndexByte(fishValueLetters, ch) >= 0 {
				if k+1 < len(v) {
					apply(ch, gluedTailToken(w, k+1), true)
				} else if i < len(args) {
					apply(ch, args[i], true)
					i++
				} else {
					apply(ch, shellToken{}, false)
				}
				break
			}
			if strings.IndexByte(fishFlagLetters, ch) < 0 {
				return unknownShellRest(c, args, i)
			}
			apply(ch, shellToken{}, false)
		}
	}
	if !c.dashC && i >= len(args) {
		c.stdin = true // fish -C CM with no -c starts a shell that reads its input
	}
	if c.dashC && i < len(args) {
		c.positionals = nonEmptyWords(args[i:])
	}
	return c
}

// shellDashCArgs returns the command texts of a POSIX shell call: the text
// of -c. words are the arguments after the program name.
func shellDashCArgs(words []shellToken) []shellToken {
	c := parsePOSIXShellCall(words)
	if !c.dashC && c.known {
		return nil
	}
	return c.commands
}

// gluedTailToken returns the word of a glued option value: the text of the
// token from byte cut, which keeps every expansion mark of the value. The cut
// cannot be placed when a mark stands at or before it, so the whole marked
// text is kept and the check fails closed on it.
func gluedTailToken(w shellToken, cut int) shellToken {
	val := w.value[cut:]
	marked := w.marked
	if i := strings.IndexByte(marked, shellUnresolvedMark); i >= 0 && i < cut {
		marked = marked[i:]
	} else if len(marked) >= cut {
		marked = marked[cut:]
	}
	if w.raw == w.value {
		return shellToken{kind: tokWord, value: val, raw: val, marked: val}
	}
	return shellToken{kind: tokWord, value: val, raw: val, marked: marked, unresolved: w.unresolved}
}

// markedAfterEq returns the marked text of a --NAME=VALUE word after the
// first "=", which keeps every expansion mark of the value.
func markedAfterEq(w shellToken) string {
	if i := strings.IndexByte(w.marked, '='); i >= 0 {
		return w.marked[i+1:]
	}
	return w.marked
}
