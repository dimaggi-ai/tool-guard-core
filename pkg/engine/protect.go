package engine

import (
	"encoding/json"
	"fmt"
	"os"
	stdpath "path"
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

	// Shell tools: a raw command string is tokenized with a real quote-aware
	// shell lexer (shell_tokenize.go) and checked for output redirections and
	// mutating commands that target a protected prefix; targets built from
	// command substitution or unresolved variables fail closed. This is a
	// detector, not a sandbox — the reliable control for arbitrary bash is to
	// scope it OUT of the write-capable policy, or use shell_classify with an
	// argv allowlist. See shellTouchesProtected for the exact shapes and the
	// documented residual limits.
	if isShellTool(tool) {
		if cmd := firstString(params, "command", "cmd"); cmd != "" {
			if hit, target := shellTouchesProtected(cmd, clean); hit {
				return true, fmt.Sprintf("protected path: shell command targets %s denied by -protect-paths", target)
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
	// This function processes POSIX shell-command text (see
	// shell_tokenize.go/protect.go's callers) - always "/"-separated,
	// regardless of what OS this binary itself runs on. filepath.IsAbs
	// alone is not sufficient to detect that: on Windows it requires a
	// drive letter and returns false for a POSIX-absolute "/protected/f",
	// which fell through to the relative-path branch below and got the
	// CWD wrongly prepended - corrupting the value into something that
	// could never match a "/"-prefixed policy prefix again. Found via a
	// real Windows CI failure: every case in shell_tokenize_test.go's
	// protected-path suite silently stopped firing on windows-latest,
	// hidden until now by an unrelated gofmt false-positive that failed
	// the job at an earlier step, before these tests ever ran.
	posixAbs := strings.HasPrefix(abs, "/")
	if posixAbs {
		// Use path.Clean (GOOS-independent, pure POSIX semantics), not
		// filepath.Clean: on Windows, filepath.Clean treats a leading "//"
		// as the start of a UNC path ("\\host\share\...") and mangles a
		// plain POSIX double-slash input like "//etc//shadow" instead of
		// just collapsing it to "/etc/shadow" - a real Windows CI failure
		// (path_classify_test.go's multi-slash case) even after
		// ToSlash-restoring the common single-slash case. path.Clean has
		// no concept of UNC paths at all, so this sidesteps that ambiguity
		// entirely rather than trying to reverse it after the fact.
		abs = stdpath.Clean(abs)
	} else {
		if !filepath.IsAbs(abs) {
			if wd, err := os.Getwd(); err == nil {
				abs = filepath.Join(wd, abs)
			}
		}
		abs = filepath.Clean(abs)
	}
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

// shellTouchesProtected reports whether a raw bash command string writes to a
// path under any protected prefix, using the real quote-aware tokenizer in
// shell_tokenize.go (which replaced the previous best-effort byte scanner).
// It fires on two shapes:
//
//  1. an output redirection whose target is under a protected prefix
//     (`echo pwned > /etc/policy.yaml`, plus `>>`, `>|`, `<>`, `&>`, `>&file`).
//  2. a known mutating command (rm, cp, mv, tee, truncate, ln, install,
//     chmod, chown, mkdir, ..., `dd of=`, `sed -i`) that carries a protected
//     path as an argument (`rm /etc/policy.yaml`).
//
// The command is tokenized ONCE and both passes run over that token stream, so
// quoting, backslash escapes, and adjacent-quote concatenation are handled
// correctly and a literal separator inside a quoted string no longer splits a
// command. Where a redirect target or a mutating-command argument is built from
// command substitution or an unresolved variable, the token is unresolved: we
// cannot prove it does NOT resolve to a protected path, so we FAIL CLOSED and
// report a hit (see shell_tokenize.go for the full rationale).
//
// This is a strict superset of the old scanner on every real write it caught.
// Where behavior differs it is only in removing the old scanner's FALSE
// positives: a `>` or `;` that lived inside quotes and was never a real
// operator (`echo '> /protected/f'`) no longer fires, and an input-redirect
// operand (`tee /tmp/out < /protected/in`) is no longer mistaken for a write.
// Neither removal can create a bypass — a command that performs no write to a
// protected path has nothing to detect.
//
// The robust control for the residual limits (an unresolved argv[0], heredoc
// bodies; see shell_tokenize.go) remains operator-side: keep bash out of the
// write-capable policy scope entirely.
func shellTouchesProtected(cmd string, prefixes []string) (bool, string) {
	return shellTouchesProtectedRec(cmd, prefixes, 0)
}

// maxShellSubstDepth bounds recursion into nested command substitutions so an
// adversarially deep `$( $( $( … ) ) )` can't exhaust the stack. Each level's
// input is a proper substring of its parent, so real commands terminate far
// below this cap; it exists only as a guard against pathological nesting.
const maxShellSubstDepth = 8

func shellTouchesProtectedRec(cmd string, prefixes []string, depth int) (bool, string) {
	toks := tokenizeShell(cmd)

	// (1) Output-redirection targets.
	for _, t := range redirectTargets(toks) {
		if t.unresolved {
			return true, shortRaw(t.raw)
		}
		if hit, target := matchLiteralPath(t.value, prefixes); hit {
			return true, target
		}
	}

	// (2) Mutating command carrying a protected path argument. Split into
	// pipeline / list segments so `ls /etc && echo hi` doesn't inherit a
	// mutating verb from a sibling segment.
	for _, seg := range splitShellSegments(toks) {
		words := stripLeadingAssignments(commandWords(seg))
		if len(words) < 2 {
			continue
		}
		vals := wordValues(words)
		prog := filepath.Base(words[0].value)
		if !isMutatingProg(prog, vals) {
			continue
		}
		for _, w := range words[1:] {
			if w.unresolved {
				return true, shortRaw(w.raw)
			}
			// Match the raw arg and, when it carries a glued path-option prefix
			// (dd of=, cp/mv/ln/install -t / --target-directory=), the path it
			// wraps. Matching both means the strip can only ADD coverage, never
			// hide a plain path.
			if hit, target := matchLiteralPath(w.value, prefixes); hit {
				return true, target
			}
			if stripped := stripPathOption(w.value); stripped != w.value {
				if hit, target := matchLiteralPath(stripped, prefixes); hit {
					return true, target
				}
			}
		}
	}

	// (3) A command substitution EXECUTES its inner command for side effects no
	// matter where the captured output goes, so a write hidden inside one —
	// `echo $(rm /protected/f)`, `x=$(rm /protected/f)`, backticks — must be
	// caught even though the output is never used as a path. Recurse into each
	// inner command (depth-bounded). Precise by construction: it fires only when
	// the inner command itself writes to a protected path, so benign
	// `echo $(date)` / `x=$(cat f)` do not fire.
	if depth < maxShellSubstDepth {
		for _, sub := range extractCommandSubsts(cmd) {
			if hit, target := shellTouchesProtectedRec(sub, prefixes, depth+1); hit {
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

// redirTarget is a redirection operand that may be a file we write, carried
// out of the token stream with its unresolved flag so the caller can fail
// closed when the target was built from an unresolved expansion.
type redirTarget struct {
	value      string
	raw        string
	unresolved bool
}

// redirectTargets extracts, from a tokenized command, every redirection operand
// that names a file we might WRITE: the operand after >, >>, >|, <>, &>, &>>,
// and after >&/<& when that operand is not a bare file descriptor. Input
// redirections (<, <<, <<-, <<<) are skipped — their operand is read, never
// written — which is why `tee /tmp/out < /protected/in` no longer spuriously
// fires on the read side. Operating on the token stream (not a raw byte scan)
// is what makes a `>` inside quotes stop counting as a redirection.
func redirectTargets(toks []shellToken) []redirTarget {
	var out []redirTarget
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tokRedirWrite && t.kind != tokRedirDup {
			continue
		}
		if i+1 >= len(toks) || toks[i+1].kind != tokWord {
			continue // malformed: operator with no word operand
		}
		operand := toks[i+1]
		if t.kind == tokRedirDup && isBareFd(operand.value) {
			continue // 2>&1, >&- : fd dup/close, not a file write
		}
		out = append(out, redirTarget{value: operand.value, raw: operand.raw, unresolved: operand.unresolved})
	}
	return out
}

// splitShellSegments groups a token stream into per-command segments, breaking
// on the control operators (; ;; & && | || |& ( ) newline). Each segment holds
// only that command's tokens (words plus its own redirections), so a mutating
// verb in one segment can't be attributed to a sibling. This replaces the old
// FieldsFunc split, which was not quote-aware and so broke `echo "a;b"` in two.
func splitShellSegments(toks []shellToken) [][]shellToken {
	var segs [][]shellToken
	var cur []shellToken
	for _, t := range toks {
		if t.kind == tokSep {
			if len(cur) > 0 {
				segs = append(segs, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
	}
	return segs
}

// commandWords reduces one segment to just its command words, dropping every
// redirection operator AND the operand word that follows it. Without this a
// redirect operand (`rm x > /protected/log`) or an input file (`< in`) would be
// mis-read as an argument to the command; write targets are checked separately
// by redirectTargets.
func commandWords(seg []shellToken) []shellToken {
	var out []shellToken
	expectOperand := false
	for _, t := range seg {
		if expectOperand {
			expectOperand = false
			if t.kind == tokWord {
				continue // this word is the redirect operand, not a command arg
			}
			// otherwise fall through: t is another operator, handled below
		}
		switch t.kind {
		case tokRedirWrite, tokRedirDup, tokRedirRead:
			expectOperand = true
		case tokWord:
			out = append(out, t)
		}
	}
	return out
}

// wordValues projects the resolved literals of a word slice, for isMutatingProg
// (which inspects flags like sed's -i and dd's of=).
func wordValues(words []shellToken) []string {
	vals := make([]string, len(words))
	for i, w := range words {
		vals[i] = w.value
	}
	return vals
}

// stripLeadingAssignments drops leading `NAME=value` variable-assignment words
// so the real program is chosen as argv[0]. In POSIX these assignments are a
// grammar production that PRECEDES the command word (`FOO=bar rm x` runs rm with
// FOO exported), so without this a mutating command hidden behind an assignment
// prefix would be misread as the non-command `FOO=bar` and slip through.
//
// Conservative on purpose: a word is treated as an assignment only when it is
// fully resolved and unquoted (raw == value, so no expansion/quoting happened)
// and its literal matches an unquoted NAME followed by '='. That mirrors bash —
// a quoted or expansion-built name is NOT an assignment — and guarantees the
// strip can only ever REVEAL the real command, never hide one (it does not
// consume the command word itself, which never contains a leading '=').
func stripLeadingAssignments(words []shellToken) []shellToken {
	i := 0
	for i < len(words) && isAssignmentWord(words[i]) {
		i++
	}
	return words[i:]
}

// isAssignmentWord reports whether w is an unquoted, fully-resolved
// `NAME=...` assignment prefix (NAME = [A-Za-z_][A-Za-z0-9_]*).
func isAssignmentWord(w shellToken) bool {
	if w.unresolved || w.value != w.raw {
		return false
	}
	eq := strings.IndexByte(w.value, '=')
	if eq <= 0 {
		return false
	}
	name := w.value[:eq]
	for j := 0; j < len(name); j++ {
		c := name[j]
		isNameOK := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(j > 0 && c >= '0' && c <= '9')
		if !isNameOK {
			return false
		}
	}
	return true
}

// stripPathOption unwraps a glued path-carrying command-line option, returning
// the filesystem path it embeds (or the arg unchanged when it carries none).
// Three shapes matter for the mutating programs we classify:
//
//   - dd's `of=FILE`
//   - GNU cp/mv/ln/install `--target-directory=DIR` (and any unambiguous
//     abbreviation `--t=DIR` … `--target-dir=DIR`, which getopt_long accepts)
//   - the glued short form `-tDIR`, including inside a short-option cluster like
//     `-rtDIR`
//
// Without this the destination directory is buried inside the option word
// (`cp secret --target-directory=/protected` writes /protected/secret) where it
// is not absolute, so canonicalCandidates would join it onto the CWD and it
// would never match a protected prefix. The space-separated forms
// (`cp -t /protected …`) already surface the path as its own word. The caller
// matches BOTH the original arg and this stripped result, so stripping can only
// widen coverage — it can never turn a real absolute path (which starts with
// '/', not 'of='/'-'/'--') into a miss.
func stripPathOption(arg string) string {
	if strings.HasPrefix(arg, "of=") {
		return arg[len("of="):]
	}
	if strings.HasPrefix(arg, "--") {
		if eq := strings.IndexByte(arg, '='); eq > 2 {
			if name := arg[2:eq]; strings.HasPrefix("target-directory", name) {
				return arg[eq+1:]
			}
		}
		return arg
	}
	if len(arg) > 1 && arg[0] == '-' {
		// -tDIR or -<flags>tDIR: the path follows the 't' in the cluster.
		if k := strings.IndexByte(arg[1:], 't'); k >= 0 && 1+k+1 < len(arg) {
			return arg[1+k+1:]
		}
	}
	return arg
}

// matchLiteralPath reports whether a fully-resolved shell word literal is under
// any protected prefix, returning the canonical form that matched. Unlike the
// old pathUnderAny it does NOT unquote: the tokenizer already stripped quotes,
// so a literal that legitimately contains a quote character (a filename with an
// embedded `"`) is matched as-is rather than re-mangled. Reuses
// canonicalCandidates + matchPathPrefix so shell tokens are canonicalized
// exactly like file-target params (absolute + symlink-resolved).
func matchLiteralPath(literal string, prefixes []string) (bool, string) {
	literal = strings.TrimSpace(literal)
	if literal == "" {
		return false, ""
	}
	for _, cand := range canonicalCandidates(literal) {
		for _, prefix := range prefixes {
			if matchPathPrefix(cand, prefix) {
				return true, cand
			}
		}
	}
	return false, ""
}

// shortRaw bounds the raw source substring reported when a token fails closed,
// so an audit reason can't be blown up by a pathologically long command
// substitution. The exact text is diagnostic only; the decision (deny) does
// not depend on it.
func shortRaw(s string) string {
	const max = 120
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
