package engine

import (
	"path"
	"regexp"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

var ghMention = regexp.MustCompile(`(?i)(^|[^a-z0-9_.-])gh(?:\.exe)?($|[^a-z0-9_.-])`)

// commandSegmentResult is test-visible so learning examples can show every
// segment, including those after the first violation. A match applies the rule effect.
type commandSegmentResult struct {
	Command string
	Match   bool
	Reason  string
}

func evalCommandClassify(c *domain.CommandClassify, fields map[string]interface{}) (bool, string) {
	if strings.TrimSpace(c.Field) == "" || c.Profile != "gh_read" {
		return true, "command_classify: invalid field or profile"
	}
	raw, ok := resolveField(c.Field, fields)
	cmd, isString := raw.(string)
	if !ok || !isString {
		return true, "command_classify: command is missing or not a string"
	}
	for _, result := range classifyCommandSegments(cmd) {
		if result.Match {
			return true, "command_classify: " + result.Reason
		}
	}
	return false, ""
}

func classifyCommandSegments(cmd string) []commandSegmentResult {
	// Check raw text before the shared tokenizer can remove continuations or
	// treat legacy arithmetic syntax as literal text.
	if strings.Contains(cmd, "\\\n") {
		return []commandSegmentResult{{cmd, true, "line continuation is not verified"}}
	}
	if strings.Contains(cmd, "$[") {
		return []commandSegmentResult{{cmd, true, "legacy arithmetic expansion is unresolved"}}
	}
	for i := 0; i < len(cmd); i++ {
		if (cmd[i] < 32 && cmd[i] != '\t' && cmd[i] != '\n') || cmd[i] == 127 {
			return []commandSegmentResult{{cmd, true, "unsupported control character"}}
		}
	}
	if strings.TrimSpace(cmd) == "" {
		return []commandSegmentResult{{cmd, true, "empty command"}}
	}
	if commandHasComment(cmd) {
		return []commandSegmentResult{{cmd, true, "shell comment is not verified"}}
	}
	var results []commandSegmentResult
	var segment []shellToken
	flush := func() {
		if len(segment) == 0 {
			return
		}
		var raw []string
		for _, t := range segment {
			if t.kind == tokWord {
				raw = append(raw, t.raw)
			} else {
				raw = append(raw, t.value)
			}
		}
		match, reason := classifyCommandSegment(segment)
		results = append(results, commandSegmentResult{strings.Join(raw, " "), match, reason})
		segment = nil
	}
	pendingCommand := false
	for _, t := range tokenizeShell(cmd) {
		if t.kind != tokSep {
			segment = append(segment, t)
			pendingCommand = false
			continue
		}
		if (t.value == "&&" || t.value == "||" || t.value == "|" || t.value == "|&" || t.value == ";" || t.value == "&") && len(segment) == 0 {
			results = append(results, commandSegmentResult{t.value, true, "control operator has no command"})
		}
		flush()
		switch t.value {
		case "|&":
			results = append(results, commandSegmentResult{t.value, true, "stderr pipe redirection is not verified"})
			pendingCommand = true
		case "&&", "||", "|":
			pendingCommand = true
		case ";", "&":
			if pendingCommand {
				results = append(results, commandSegmentResult{t.value, true, "control operator has no command"})
			}
		case "\n":
		default:
			results = append(results, commandSegmentResult{t.value, true, "unsupported shell control syntax"})
		}
	}
	flush()
	if pendingCommand {
		results = append(results, commandSegmentResult{cmd, true, "control operator has no following command"})
	}
	if len(results) == 0 {
		results = append(results, commandSegmentResult{cmd, true, "empty command"})
	}
	return results
}

// Check comments before tokenization: quotes in a comment must not hide later
// commands by being interpreted as quotes that span a newline.
func commandHasComment(cmd string) bool {
	var quote byte
	wordStart := true
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote == '\'' {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\\' && (quote == 0 || (i+1 < len(cmd) && isDquoteEscape(cmd[i+1]))) {
			if i+1 < len(cmd) && cmd[i+1] != '\n' {
				wordStart = false
			}
			i++
			continue
		}
		if quote == '"' {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '#' && wordStart {
			return true
		}
		if c == '\'' || c == '"' {
			quote = c
		}
		wordStart = strings.ContainsRune(" \t\n;&|()<>", rune(c))
	}
	return false
}

var commandMentionText = strings.NewReplacer("\\\n", "", "'", "", "\"", "", "\\", "")

func classifyCommandSegment(tokens []shellToken) (bool, string) {
	for _, t := range tokens {
		if strings.Contains(t.raw, "$'") || strings.Contains(t.raw, "$\"") {
			return true, "ANSI-C or locale quoting is not verified"
		}
		// Reject substitutions even in otherwise unrelated commands. Inspecting
		// their output cannot establish that executing their bodies is read-only.
		if strings.Contains(t.raw, "$(") || strings.ContainsAny(t.raw, "`{}") || strings.HasPrefix(t.value, "<<") {
			return true, "substitution, group or here-document is unresolved"
		}
	}
	words := commandWords(tokens)
	if len(words) == 0 {
		return true, "segment has no literal program"
	}
	head := words[0]
	program := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(head.value, "\\", "/"))), ".exe")
	if program == "gh" && head.raw != "gh" {
		return true, "gh program name is not the exact literal gh"
	}
	if head.unresolved || head.raw != head.value || strings.ContainsAny(head.raw, "*?[]~\\") {
		return true, "program name is not a bare literal"
	}
	switch path.Base(head.value) {
	case "eval", "fc", "sh", "bash", "env", "command", "exec", "xargs", "sudo", "nohup", "time",
		"nice", "timeout", "source", ".", "builtin", "alias", "unalias", "hash", "enable",
		"export", "unset", "set", "shopt", "declare", "typeset", "local", "readonly",
		"zsh", "dash", "ksh", "fish", "watch", "parallel", "runuser", "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "function", "!", "coproc", "select":
		return true, "wrapper or shell grammar is not verified"
	}
	if strings.Contains(head.value, "=") {
		return true, "assignment scope is unresolved"
	}
	if program != "gh" {
		for _, t := range tokens {
			if t.kind != tokWord {
				continue
			}
			if ghMention.MatchString(t.raw) || ghMention.MatchString(t.value) || ghMention.MatchString(commandMentionText.Replace(t.raw)) {
				return true, "gh appears inside another command"
			}
			if t.unresolved || !commandLiteral(t.raw) {
				return true, "unresolved word in another command"
			}
		}
		for _, t := range tokens {
			if t.kind != tokWord {
				return true, "redirection in helper segment is not verified"
			}
		}
		if head.raw == "jq" && len(words) == 2 && words[1].value == ".title" {
			return false, "verified jq .title helper"
		}
		return true, "unsupported command form"
	}
	for _, t := range tokens {
		if t.kind != tokWord {
			return true, "redirection in gh segment is not verified"
		}
		if t.unresolved || !commandLiteral(t.raw) {
			return true, "gh argument is unresolved or malformed"
		}
	}
	return classifyGH(wordValues(words)[1:])
}

// commandLiteral checks the syntax the shared detector intentionally tolerates:
// unmatched quotes, trailing escapes and runtime glob/tilde expansion. It does
// not resolve any expansion. Quoted query punctuation remains literal.
// It also rejects unquoted characters that zsh can expand under EXTENDED_GLOB
// (`^`, `#`), EQUALS and MAGIC_EQUAL_SUBST (`=` at word start or after an
// unquoted `=` or `:`) and history expansion (`!` outside single quotes).
// Empty quotes do not end a word start or separate an `=` from what precedes it.
func commandLiteral(raw string) bool {
	var quote byte
	start, afterAssign := true, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote == '\'' {
			if c == quote {
				quote = 0
				continue
			}
			start, afterAssign = false, false
			continue
		}
		if c == '\\' {
			i++
			if i == len(raw) {
				return false
			}
			start, afterAssign = false, false
			continue
		}
		if quote == '"' {
			if c == quote {
				quote = 0
				continue
			}
			if c == '!' {
				return false
			}
			start, afterAssign = false, false
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if strings.ContainsRune("*?[]~^#!", rune(c)) || c == '=' && (start || afterAssign) {
			return false
		}
		start, afterAssign = false, c == '=' || c == ':'
	}
	return quote == 0
}

// Flags are a deliberately small subset of gh 2.102.0 (2026-09-30) manual pages:
// gh-pr, gh-issue, gh-repo, gh-release and gh-api. Unknown flags never pass.
// Values are consumed before deciding which words name commands or endpoints.
func ghFlag(name, group, verb string) (takesValue, known bool) {
	switch name {
	case "--repo", "-R":
		return true, group == "" || group == "pr" || group == "issue" || group == "release"
	case "--help":
		return false, true
	}
	if !ghReadVerb(group, verb) {
		return false, false
	}
	if verb != "diff" {
		switch name {
		case "--json", "--jq", "-q":
			return true, true
		}
	}
	if (group == "pr" || group == "issue") && verb == "view" {
		switch name {
		case "--comments", "-c":
			return false, true
		}
	}
	if verb == "list" {
		switch name {
		case "--limit", "-L":
			return true, true
		}
	}
	if (group == "pr" || group == "issue") && verb == "list" {
		switch name {
		case "--state", "-s", "--assignee", "-a", "--author", "-A", "--label", "-l", "--search", "-S":
			return true, true
		}
	}
	if group == "pr" && verb == "diff" {
		switch name {
		case "--color":
			return true, true
		case "--patch", "--name-only":
			return false, true
		}
	}
	if group == "pr" && verb == "checks" && name == "--required" {
		return false, true
	}
	return false, false
}

func ghReadVerb(group, verb string) bool {
	switch group {
	case "pr":
		return verb == "view" || verb == "list" || verb == "status" || verb == "diff" || verb == "checks"
	case "issue":
		return verb == "view" || verb == "list" || verb == "status"
	case "repo", "release":
		return verb == "view" || verb == "list"
	}
	return false
}

func classifyGH(args []string) (bool, string) {
	group, verb := "", ""
	var operands []string
	var parsedFlags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			// Short clusters are parsed one letter at a time. Value-taking flags
			// consume the remaining suffix, so -iXPATCH cannot hide a method.
			flags := []string{arg}
			short := !strings.HasPrefix(arg, "--")
			if short {
				flags = nil
				for j := 1; j < len(arg); j++ {
					name := "-" + string(arg[j])
					flags = append(flags, name)
					takesValue, known := ghFlag(name, group, verb)
					if !known {
						return true, "unknown gh option"
					}
					if takesValue {
						if j+1 < len(arg) {
							flags[len(flags)-1] += "=" + strings.TrimPrefix(arg[j+1:], "=")
						}
						break
					}
				}
				if len(flags) == 0 {
					return true, "unsupported gh option form"
				}
			}
			for _, flag := range flags {
				name, value, attached := strings.Cut(flag, "=")
				parsedFlags = append(parsedFlags, name)
				takesValue, known := ghFlag(name, group, verb)
				if !known {
					return true, "unknown gh option"
				}
				if takesValue {
					if !attached {
						i++
						if i >= len(args) {
							return true, "missing gh option value"
						}
						value = args[i]
					}
					if value == "" || strings.HasPrefix(value, "-") {
						return true, "invalid gh option value"
					}
				} else if attached {
					return true, "unsupported boolean option value"
				}
			}
			continue
		}
		if group == "" {
			if arg == "" {
				return true, "empty gh command argument"
			}
			group = arg
			continue
		}
		if group != "api" && verb == "" {
			if arg == "" {
				return true, "empty gh command argument"
			}
			verb = arg
			if (group == "pr" || group == "issue") && verb == "new" {
				verb = "create"
			}
			if (group == "pr" || group == "issue" || group == "repo" || group == "release") && verb == "ls" {
				verb = "list"
			}
			continue
		}
		operands = append(operands, arg)
	}
	// Selectors may precede the command group, but must belong to the final command.
	for _, name := range parsedFlags {
		if _, known := ghFlag(name, group, verb); !known {
			return true, "unknown gh option"
		}
	}
	// No host or route allowlist is approved, path shape does not establish API
	// semantics, and ambient GH_HOST or gh configuration is not observable.
	if group == "api" {
		return true, "gh api is not verified"
	}
	if !ghReadVerb(group, verb) {
		return true, "gh operation is not a verified read"
	}
	maxOperands := 1
	if verb == "status" || (verb == "list" && group != "repo") {
		maxOperands = 0
	}
	if len(operands) > maxOperands || (group == "issue" && verb == "view" && len(operands) != 1) {
		return true, "unsupported gh operands"
	}
	return false, "verified gh " + group + " " + verb
}
