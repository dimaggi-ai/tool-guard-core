package engine

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ViolatesProtectedPaths reports whether a write-capable tool call targets
// any of the protected path prefixes and, if so, a human-readable reason.
//
// This is the "self-protection" primitive behind tg hook's -protect-paths /
// -protect-self and tg-proxy's matching flags. The core insight from
// dogfooding: any protection written INSIDE a policy is useless because the
// agent can just edit the policy. So this check lives in operator flags and
// runs BEFORE (and independent of) policy evaluation — a policy can never
// turn it off.
//
// prefixes are canonical path prefixes. They are filepath.Clean'd here so
// the caller can pass raw operator input. An empty prefix list (the common
// case) is a fast no-op.
//
// Matching semantics reuse matchPathPrefix from path_classify.go: exact
// path match, component-boundary prefix match, and "*"/"**" wildcards.
func ViolatesProtectedPaths(env *domain.ActionEnvelope, prefixes []string) (bool, string) {
	if env == nil || len(prefixes) == 0 {
		return false, ""
	}
	clean := cleanPrefixes(prefixes)
	if len(clean) == 0 {
		return false, ""
	}

	params := parseParams(env.Parameters)
	tool := strings.ToLower(strings.TrimSpace(env.ToolName))

	// File-target tools: write / edit / notebookedit and any tool whose
	// params carry a file_path / path. Known read-only tools (read, glob,
	// grep, ...) are excluded so the guard protects against WRITES without
	// breaking a legitimate read of the policy dir.
	if fp := firstString(params, "file_path", "path"); fp != "" && isFileWriteTool(tool) {
		cleaned := filepath.Clean(fp)
		for _, prefix := range clean {
			if matchPathPrefix(cleaned, prefix) {
				return true, fmt.Sprintf("protected path: write to %s denied by -protect-paths", cleaned)
			}
		}
	}

	// Shell tools: best-effort. Robust shell protection is a non-goal — the
	// reliable answer is to scope bash OUT of the write-capable policy, or
	// use shell_classify with an argv allowlist. Here we only catch the
	// obvious `echo x > /protected/file` and `rm /protected/file` shapes so
	// a careless agent can't trivially trample a protected file. See
	// shellTouchesProtected for the exact heuristics and their limits.
	if isShellTool(tool) {
		if cmd := firstString(params, "command", "cmd"); cmd != "" {
			if hit, target := shellTouchesProtected(cmd, clean); hit {
				return true, fmt.Sprintf("protected path: shell command targets %s denied by -protect-paths (best-effort match)", target)
			}
		}
	}

	return false, ""
}

// cleanPrefixes trims, drops empties, and filepath.Clean's each prefix.
func cleanPrefixes(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// parseParams unmarshals the envelope's Parameters into a string-keyed map.
// A non-object / absent payload yields an empty map (nothing to protect).
func parseParams(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]interface{}{}
	}
	return m
}

// firstString returns the first non-empty string value among keys.
func firstString(params map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := params[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

// isFileWriteTool reports whether a tool that carries a file_path/path
// should be treated as write-capable. write/edit/notebookedit and any
// unknown tool are treated as writers (fail-safe); known read-only tools
// are excluded so protecting a path does not block reading it.
func isFileWriteTool(tool string) bool {
	switch tool {
	case "read", "readfile", "read_file", "glob", "grep", "ls", "list",
		"cat", "view", "search", "get", "fetch", "webfetch", "websearch":
		return false
	}
	return true
}

// isShellTool reports whether the tool executes a shell command string.
func isShellTool(tool string) bool {
	switch tool {
	case "bash", "shell", "sh", "run_command", "run", "exec", "command", "terminal":
		return true
	}
	return false
}

// shellTouchesProtected is the best-effort shell scanner. It fires on two
// shapes only:
//
//  1. a write redirection (`>` / `>>`) whose target is under a protected
//     prefix, e.g. `echo pwned > /etc/policy.yaml`.
//  2. a known mutating command (rm, cp, mv, tee, truncate, ln, install,
//     chmod, chown, mkdir, ..., `dd of=`, `sed -i`) that carries a
//     protected path as an argument, e.g. `rm /etc/policy.yaml`.
//
// It is deliberately conservative and NOT a shell parser: quoting, command
// substitution, variable expansion, and ~ expansion are not resolved, so a
// determined agent can evade it. That is acceptable — this exists to stop
// the obvious footgun, not to be a shell sandbox. The robust control is to
// keep bash out of the write-capable policy scope entirely.
func shellTouchesProtected(cmd string, prefixes []string) (bool, string) {
	// (1) redirection targets.
	for _, t := range redirectTargets(cmd) {
		if hit, target := pathUnderAny(t, prefixes); hit {
			return true, target
		}
	}
	// (2) mutating command with a protected path argument. Split into
	// pipeline / list segments so `ls /etc && echo hi` doesn't inherit a
	// mutating verb from a sibling segment.
	for _, seg := range splitShellSegments(cmd) {
		fields := strings.Fields(seg)
		if len(fields) < 2 {
			continue
		}
		prog := filepath.Base(unquote(fields[0]))
		if !isMutatingProg(prog, fields) {
			continue
		}
		for _, f := range fields[1:] {
			arg := f
			if strings.HasPrefix(arg, "of=") { // dd of=/path
				arg = arg[len("of="):]
			}
			if hit, target := pathUnderAny(arg, prefixes); hit {
				return true, target
			}
		}
	}
	return false, ""
}

// mutatingProgs are argv[0] program names that create/modify/delete files.
// sed and dd are handled specially (only mutating with -i / of=).
var mutatingProgs = map[string]bool{
	"rm": true, "cp": true, "mv": true, "tee": true, "truncate": true,
	"ln": true, "install": true, "chmod": true, "chown": true, "chgrp": true,
	"mkdir": true, "rmdir": true, "touch": true, "shred": true,
}

func isMutatingProg(prog string, fields []string) bool {
	if mutatingProgs[prog] {
		return true
	}
	switch prog {
	case "sed":
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-i") { // -i, -i.bak, -ie ...
				return true
			}
		}
	case "dd":
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "of=") {
				return true
			}
		}
	}
	return false
}

// pathUnderAny cleans a shell token and reports whether it is under any
// protected prefix, returning the cleaned token that matched.
func pathUnderAny(tok string, prefixes []string) (bool, string) {
	tok = unquote(strings.TrimSpace(tok))
	if tok == "" {
		return false, ""
	}
	cleaned := filepath.Clean(tok)
	for _, prefix := range prefixes {
		if matchPathPrefix(cleaned, prefix) {
			return true, cleaned
		}
	}
	return false, ""
}

// redirectTargets extracts the filename token following each `>` / `>>`.
// It skips fd-dup forms (`>&2`) and returns the raw token (still possibly
// quoted); pathUnderAny unquotes it.
func redirectTargets(cmd string) []string {
	var out []string
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != '>' {
			continue
		}
		j := i + 1
		if j < len(cmd) && cmd[j] == '>' { // ">>"
			j++
		}
		if j < len(cmd) && cmd[j] == '&' { // ">&" fd-dup, not a file
			i = j
			continue
		}
		for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
			j++
		}
		start := j
		for j < len(cmd) && !isShellSep(cmd[j]) {
			j++
		}
		if j > start {
			out = append(out, cmd[start:j])
		}
		i = j
	}
	return out
}

// splitShellSegments splits a command line into pipeline/list segments on
// the shell separators ; | & and newlines (covering && and || as runs).
func splitShellSegments(cmd string) []string {
	return strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case ';', '|', '&', '\n', '\r':
			return true
		}
		return false
	})
}

// isShellSep reports whether b terminates a shell word for the purposes of
// redirect-target extraction.
func isShellSep(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '<', '>':
		return true
	}
	return false
}

// unquote strips a single pair of surrounding single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
