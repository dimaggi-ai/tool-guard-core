package engine

import (
	"encoding/json"
	"fmt"
	"os"
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
//
// Canonicalization (hardened after adversarial review): both the candidate
// path and every protected prefix are made absolute (relative paths resolve
// against the process CWD) and symlink-resolved on their longest existing
// ancestor, then matched in every combination. This closes the relative-path
// (`file_path: "policy.yaml"`) and symlink-traversal (`/tmp/link/x` where
// /tmp/link -> /protected) bypasses.
//
// TRUST MODEL: the read-only tool exclusion (read/grep/…) trusts that
// env.ToolName is set by the agent RUNTIME / tool adapter, not chosen by the
// model. Unknown tools default to write-capable (fail-safe), so the only way
// a "read" name reaches a write is if the runtime itself mislabels a writing
// tool as "read" — out of scope for this primitive. If ToolName is
// model-controlled in your deployment, do not rely on the exclusion; scope
// writers explicitly instead.
//
// OUT OF SCOPE: case-insensitive / Unicode-normalizing filesystems (matching
// is byte-exact; Linux is case-sensitive) and percent-encoded path forms.
func ViolatesProtectedPaths(env *domain.ActionEnvelope, prefixes []string) (bool, string) {
	if env == nil || len(prefixes) == 0 {
		return false, ""
	}
	clean := expandPrefixes(prefixes)
	if len(clean) == 0 {
		return false, ""
	}

	params := parseParams(env.Parameters)
	tool := strings.ToLower(strings.TrimSpace(env.ToolName))

	// File-target tools: write / edit / notebookedit and any tool whose
	// params carry a file_path / path (including arrays and one level of
	// nested edit objects). Known read-only tools (read, glob, grep, ...)
	// are excluded so the guard protects against WRITES without breaking a
	// legitimate read of the policy dir.
	if isFileWriteTool(tool) {
		for _, fp := range collectFilePaths(params) {
			for _, cand := range canonicalCandidates(fp) {
				for _, prefix := range clean {
					if matchPathPrefix(cand, prefix) {
						return true, fmt.Sprintf("protected path: write to %s denied by -protect-paths", cand)
					}
				}
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

// expandPrefixes trims, drops empties, and produces the canonical forms of
// each prefix: absolute-cleaned plus (when different) symlink-resolved. A
// prefix that is itself a symlink or a relative path is thus matched against
// the equally-canonicalized candidate paths.
func expandPrefixes(prefixes []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for _, c := range canonicalCandidates(p) {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// canonicalCandidates returns the canonical path forms to match: the
// absolute-cleaned path and, when it differs, the symlink-resolved path.
// Relative inputs resolve against the process CWD. Both forms are returned
// so a symlink can neither add a match (traversal) nor remove one (the
// textual form is always tested, so resolution failure never fails open).
func canonicalCandidates(p string) []string {
	abs := p
	if !filepath.IsAbs(abs) {
		if wd, err := os.Getwd(); err == nil {
			abs = filepath.Join(wd, abs)
		}
	}
	abs = filepath.Clean(abs)
	out := []string{abs}
	if resolved := resolveSymlinksBestEffort(abs); resolved != "" && resolved != abs {
		out = append(out, resolved)
	}
	return out
}

// resolveSymlinksBestEffort resolves symlinks on the longest existing
// ancestor of an absolute path and re-appends the remaining (possibly
// not-yet-created) components. Write targets often don't exist yet, so a
// plain EvalSymlinks would fail; walking up to the deepest existing ancestor
// still catches `/tmp/link/newfile` where /tmp/link is a symlink. Returns ""
// when nothing resolves (caller keeps the textual form).
func resolveSymlinksBestEffort(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(r)
	}
	parent := p
	suffix := ""
	for {
		np := filepath.Dir(parent)
		if np == parent { // reached root with nothing resolvable
			return ""
		}
		if suffix == "" {
			suffix = filepath.Base(parent)
		} else {
			suffix = filepath.Join(filepath.Base(parent), suffix)
		}
		parent = np
		if r, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Clean(filepath.Join(r, suffix))
		}
	}
}

// collectFilePaths gathers path-shaped strings from the write params of a
// tool call: the flat file_path/path/etc. keys, string arrays under
// paths/files, and one level of nested edit objects (multiedit-style
// edits:[{file_path:…}]). Not a general crawler — bounded to the shapes
// coding-agent tools actually use.
func collectFilePaths(params map[string]interface{}) []string {
	var out []string
	add := func(v interface{}) {
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out = append(out, t)
			}
		case []interface{}:
			for _, e := range t {
				if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, s)
				}
			}
		}
	}
	for _, k := range []string{
		"file_path", "path", "paths", "file", "files", "filename",
		"dest", "destination", "target", "output", "out_path", "notebook_path",
	} {
		if v, ok := params[k]; ok {
			add(v)
		}
	}
	// One level of nested edit/operation objects.
	for _, k := range []string{"edits", "files", "changes", "operations"} {
		arr, ok := params[k].([]interface{})
		if !ok {
			continue
		}
		for _, e := range arr {
			if m, ok := e.(map[string]interface{}); ok {
				if s := firstString(m, "file_path", "path", "file"); s != "" {
					out = append(out, s)
				}
			}
		}
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

// pathUnderAny canonicalizes a shell token (absolute + symlink-resolved,
// same as file-target matching) and reports whether any form is under a
// protected prefix, returning the form that matched.
func pathUnderAny(tok string, prefixes []string) (bool, string) {
	tok = unquote(strings.TrimSpace(tok))
	if tok == "" {
		return false, ""
	}
	for _, cand := range canonicalCandidates(tok) {
		for _, prefix := range prefixes {
			if matchPathPrefix(cand, prefix) {
				return true, cand
			}
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
