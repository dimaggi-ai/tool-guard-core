package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	stdpath "path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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
// ancestor, then matched in every combination. A path with a ".." part is
// also walked one part at a time (physicalPath), because the kernel follows
// a link before "..". This closes the relative-path
// (`file_path: "policy.yaml"`) and symlink-traversal (`/tmp/link/x` where
// /tmp/link -> /protected, `/var/run/../protected/x`) bypasses.
//
// TRUST MODEL: the read-only tool exclusion (read/grep/…) trusts that
// env.ToolName is set by the agent RUNTIME / tool adapter, not chosen by the
// model. Unknown tools default to write-capable (fail-safe), so the only way
// a "read" name reaches a write is if the runtime itself mislabels a writing
// tool as "read" — out of scope for this primitive. If ToolName is
// model-controlled in your deployment, do not rely on the exclusion; scope
// writers explicitly instead.
//
// LETTER CASE: where the file system of a protected path ignores letter
// case (macOS, Windows, or a directory found to do so), paths are also
// compared in lower case (matchProtected).
//
// OUT OF SCOPE: Unicode-normalizing filesystems and percent-encoded path
// forms.
func ViolatesProtectedPaths(env *domain.ActionEnvelope, prefixes []string) (bool, string) {
	if env == nil || len(prefixes) == 0 {
		return false, ""
	}
	// The check reads the file system and can be made slow by a long
	// command. A check that does not end in protectBudget, or that panics,
	// is a deny: the caller has a time limit of its own, and past it the
	// call would run unchecked.
	type verdict struct {
		hit    bool
		reason string
	}
	done := make(chan verdict, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- verdict{true, "protected path: the check failed, so the call is denied by -protect-paths"}
			}
		}()
		hit, reason := violatesProtectedPaths(env, prefixes)
		done <- verdict{hit, reason}
	}()
	select {
	case v := <-done:
		return v.hit, v.reason
	case <-time.After(protectBudget):
		return true, fmt.Sprintf("protected path: the check did not end in %s, so the call is denied by -protect-paths", protectBudget)
	}
}

// protectBudget is the time one call of ViolatesProtectedPaths may take. A
// test replaces it.
var protectBudget = 10 * time.Second

// maxResolvePathLen is the longest path whose symbolic links are followed.
// One system call takes at most 4096 bytes; the room above that is for a
// relative path joined to a directory.
const maxResolvePathLen = 4 * 4096

// workDirParamNames are the parameter names, in lower case and without
// "_", "-", "." and blanks, that hold the directory a tool call runs in.
// `tg hook` adds the directory the harness reports as "cwd".
var workDirParamNames = map[string]bool{
	"cwd": true, "workdir": true, "workingdir": true, "workingdirectory": true,
}

// paramWorkDirs returns the directories the call says it runs in, other than
// the directory of this process. A relative value is also read under each
// absolute one.
func paramWorkDirs(params map[string]interface{}) []string {
	var raw []string
	for k, v := range params {
		var b strings.Builder
		for _, r := range k {
			if !strings.ContainsRune("_-. ", r) {
				b.WriteRune(unicode.ToLower(r))
			}
		}
		if !workDirParamNames[b.String()] {
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			raw = append(raw, strings.TrimSpace(s))
		}
	}
	sort.Strings(raw)
	var out []string
	for _, d := range raw {
		if !containsString(out, d) {
			out = append(out, d)
		}
		if !strings.HasPrefix(d, "/") {
			for _, abs := range raw {
				if joined := strings.TrimRight(abs, "/") + "/" + d; strings.HasPrefix(abs, "/") && !containsString(out, joined) {
					out = append(out, joined)
				}
			}
		}
	}
	// The directory of this process is read in every case.
	if wd, err := os.Getwd(); err == nil {
		kept := out[:0]
		for _, d := range out {
			if stdpath.Clean(d) != filepath.ToSlash(wd) {
				kept = append(kept, d)
			}
		}
		out = kept
	}
	return out
}

// selfCwdRest returns what follows "/proc/self/cwd" or
// "/proc/thread-self/cwd" at the start of a path.
func selfCwdRest(p string) (string, bool) {
	p = collapseSlashDots(p)
	for _, head := range []string{"/proc/self/cwd", "/proc/thread-self/cwd"} {
		if p == head || strings.HasPrefix(p, head+"/") {
			return p[len(head):], true
		}
	}
	return "", false
}

// pathReadings returns the path of a write tool as written, and under each
// directory the call says it runs in: a relative path, and a path through
// the working directory of the process that will open it.
func pathReadings(p string, dirs []string) []string {
	out := []string{p}
	for _, d := range dirs {
		d = strings.TrimRight(d, "/")
		if rest, ok := selfCwdRest(p); ok {
			out = append(out, d+rest)
		} else if !strings.HasPrefix(p, "/") && !filepath.IsAbs(p) {
			out = append(out, d+"/"+p)
		}
	}
	return out
}

func violatesProtectedPaths(env *domain.ActionEnvelope, prefixes []string) (bool, string) {
	clean := expandPrefixes(prefixes)
	if len(clean) == 0 {
		return false, ""
	}

	params := parseParams(env.Parameters)
	tool := strings.ToLower(strings.TrimSpace(env.ToolName))
	dirs := paramWorkDirs(params)

	// File-target tools: write / edit / notebookedit and any tool whose
	// params carry a file_path / path (including arrays and one level of
	// nested edit objects). Known read-only tools (read, glob, grep, ...)
	// are excluded so the guard protects against WRITES without breaking a
	// legitimate read of the policy dir.
	if isFileWriteTool(tool) {
		for _, fp := range collectFilePaths(params) {
			// A path through another process's working directory or an
			// open descriptor names a directory not known here.
			rest, self := selfCwdRest(fp)
			if !self && (procPathUnknown(fp) || procDirUnknown(fp)) {
				return true, fmt.Sprintf("protected path: write through %s denied by -protect-paths (directory not known)", shortRaw(fp))
			}
			readings := pathReadings(fp, dirs)
			// A path through /proc/self/cwd is the path under the directory
			// of the process that opens it. That process can be this one
			// (the hook runs in the agent's directory) or one in a directory
			// the call names, so each of them is read. A ".." after it gives
			// the physical parent of that directory, which the text does not
			// show, and the path as written stays in the list (unknown, deny).
			// If the directory of this process is not known, the same holds.
			if self && !strings.Contains(rest+"/", "/../") {
				if wd, err := os.Getwd(); err == nil {
					readings[0] = strings.TrimRight(filepath.ToSlash(wd), "/") + rest
				}
			}
			for _, reading := range readings {
				if linkIntoProc(reading) {
					return true, fmt.Sprintf("protected path: write through %s denied by -protect-paths (directory not known)", shortRaw(reading))
				}
				// The same path under the directory the call says it runs
				// in can go through /proc or /dev/fd (cwd "/proc/self"
				// with file "cwd/P", cwd "/dev/fd/3" with file "P"), so
				// the unknown directory is checked on every reading, not
				// only on the path as written.
				if procPathUnknown(reading) || procDirUnknown(reading) {
					return true, fmt.Sprintf("protected path: write through %s denied by -protect-paths (directory not known)", shortRaw(reading))
				}
				for _, cand := range canonicalCandidates(reading) {
					for _, prefix := range clean {
						if matchProtected(cand, prefix) {
							return true, fmt.Sprintf("protected path: write to %s denied by -protect-paths", cand)
						}
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
	//
	// A tool that is only in the group "shell" has a name `tg hook` does not
	// know. It can be a shell, and its command can be text in another
	// language (SQL, JavaScript), where ">" and "$" are not shell syntax. So
	// a hit counts only when the text names a protected path. A tool with a
	// read-only name is not checked.
	shellTool := IsShellTool(tool)
	groupShell := !shellTool && strings.EqualFold(strings.TrimSpace(env.ToolGroup), "shell") && isFileWriteTool(tool)
	if shellTool || groupShell {
		if cmd := firstString(params, "command", "cmd"); cmd != "" {
			hit, target := shellTouchesProtectedRec(cmd, clean, 0, nil, dirs)
			if hit && groupShell && !commandTextNamesProtected(cmd, clean, dirs) {
				hit = false
			}
			if hit {
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
	out := canonicalCandidatesLexical(p)
	// path.Clean drops "LINK/.." as text. The kernel follows LINK first,
	// so "/var/run/../x" can be a file that the cleaned path does not name.
	if phys := physicalPath(p); phys != "" {
		for _, c := range append([]string{phys}, resolveSymlinksBestEffort(phys)) {
			if c != "" && !containsString(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// evalSymlinkCached is filepath.EvalSymlinks with the results of one check
// kept: a long brace list asks the same prefix thousands of times, and one
// system call per word costs seconds against protectBudget. The cache is the
// map handed in and lives only for one check; a negative result is kept as
// "" so a failed lookup is not tried again.
func evalSymlinkCached(cache map[string]string, p string) (string, bool) {
	if r, ok := cache[p]; ok {
		return r, r != ""
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		cache[p] = ""
		return "", false
	}
	cache[p] = filepath.ToSlash(r)
	return cache[p], true
}

// physicalPath walks a path that has a ".." part one part at a time and
// follows symbolic links before each "..". It returns "" for a path with no
// ".." part, because resolveSymlinksBestEffort covers that case. A part that
// does not exist is kept as text.
func physicalPath(p string) string {
	return physicalPathCached(p, map[string]string{})
}

// physicalPathCached is physicalPath with a cache of the EvalSymlinks calls,
// so a caller that walks many words over the same prefix pays for each
// directory once.
func physicalPathCached(p string, cache map[string]string) string {
	hasDotDot := false
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			hasDotDot = true
		}
	}
	if !hasDotDot || len(p) > maxResolvePathLen {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		// A Windows drive path (C:\dir\..\x, C:dir\..\x) carries its own
		// place in its text, and the check reads such paths with POSIX
		// separators (decodeWindowsShellEscapes turns the backslashes of the
		// command into "/"), so path.Clean resolves their ".." parts. The
		// volume test is made on the raw text, because filepath.VolumeName
		// is built for the separators of the host and reads nothing in
		// "C:/dir" on a POSIX host.
		if v := volumeNameOf(p); v != "" && len(v) == 2 && v[1] == ':' {
			return filepath.Clean(p)
		}
		if filepath.IsAbs(p) {
			return ""
		}
		wd, err := os.Getwd()
		if err != nil {
			return ""
		}
		p = filepath.ToSlash(wd) + "/" + p
	}
	root := "/"
	if vol := filepath.VolumeName(p); vol != "" {
		root = vol + "/"
		p = p[len(vol):]
	}
	// The parts are kept in a slice: a join per part is quadratic in the
	// length of the path.
	var parts []string
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".":
		case "..":
			cur := root + strings.Join(parts, "/")
			if r, ok := evalSymlinkCached(cache, cur); ok {
				// The resolved text carries a volume only when the host has
				// one. Cutting the volume of the resolved text off it, and
				// then the volume of the path read when the resolved text
				// repeats it, keeps every real directory name of the path.
				res := r[len(filepath.VolumeName(r)):]
				if vol := volumeNameOf(p); vol != "" && strings.HasPrefix(res, vol) {
					res = res[len(vol):]
				}
				parts = parts[:0]
				for _, rp := range strings.Split(res, "/") {
					if rp != "" {
						parts = append(parts, rp)
					}
				}
			}
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, part)
		}
	}
	return root + strings.Join(parts, "/")
}

func canonicalCandidatesLexical(p string) []string {
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
	if len(p) > maxResolvePathLen {
		return "" // no system call takes a path this long
	}
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

// IsShellTool reports whether the tool name is a known shell tool, i.e. one
// that executes a shell command string.
// `powershell` and `pwsh` are here because a PowerShell tool call still
// carries shell redirection: without them, `echo x > <protected path>` sent
// as a PowerShell tool call was allowed while the same string as a Bash tool
// call was denied. Measured 2026-11-09. This does NOT mean PowerShell
// cmdlets are understood — Set-Content, Out-File and Remove-Item are still
// not parsed as writes, and such commands escalate rather than deny.
// `run_shell_command` is the Gemini CLI shell tool name.
// ViolatesProtectedPaths also runs the shell check for a tool whose group is
// "shell", which is the group `tg hook` gives a tool name it does not know.
func IsShellTool(tool string) bool {
	switch tool {
	case "bash", "shell", "sh", "run_command", "run_shell_command", "run", "exec", "command", "terminal":
		return true
	case "exec_command", "shell_command", "local_shell", "unified_exec", "container.exec":
		return true
	case "powershell", "pwsh":
		return true
	}
	return false
}

// shellTouchesProtected reports whether a raw bash command string writes to a
// path under any protected prefix, using the real quote-aware tokenizer in
// shell_tokenize.go (which replaced the previous best-effort byte scanner).
// It fires on the shapes below, and also on the command a shell runs with -c
// (shellDashCArgs) and on a directory operand above a protected path
// (directoryOperandTouchesProtected):
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
// After these passes the name rule of protect_mention.go runs: a command
// whose text names a protected path is denied unless every program in it is
// read-only. The limits that remain are in the section "Protected paths" of
// examples/coding-agent-guard/README.md. The robust control for them is
// operator-side: keep bash out of the write-capable policy scope entirely.
func shellTouchesProtected(cmd string, prefixes []string) (bool, string) {
	return shellTouchesProtectedRec(cmd, prefixes, 0, nil, nil)
}

// maxShellSubstDepth bounds recursion into nested command substitutions and
// nested sh -c commands so an adversarially deep `$( $( $( … ) ) )` can't
// exhaust the stack. Each level's input is a proper substring of its parent,
// so real commands terminate far below this cap. A command that still holds a
// substitution or a sh -c command at the cap is not read further and fails
// closed.
const maxShellSubstDepth = 8

// shellTouchesProtectedRec is the check of one command text. inherited are
// the directories found in the command around it. work are the directories
// the tool call says it runs in.
func shellTouchesProtectedRec(cmd string, prefixes []string, depth int, inherited, work []string) (bool, string) {
	if hit, reason := shellTouchesProtectedPOSIX(cmd, prefixes, depth, inherited, work); hit {
		return true, reason
	}
	// Native Windows shells retain backslashes as path separators. Check
	// that reading as well; replacing the POSIX reading would lose escaped
	// command names and paths used by POSIX shells running on Windows.
	if runtime.GOOS == "windows" && depth == 0 && strings.Contains(cmd, `\`) {
		for _, text := range []string{cmd, decodeWindowsShellEscapes(cmd)} {
			if hit, reason := shellTouchesProtectedPOSIX(strings.ReplaceAll(text, `\`, "/"), prefixes, depth, inherited, work); hit {
				return true, reason
			}
		}
	}
	return false, ""
}

func shellTouchesProtectedPOSIX(cmd string, prefixes []string, depth int, inherited, work []string) (bool, string) {
	toks := tokenizeShell(cmd)
	frags, homeAlts, over := shellFragments(cmd)
	if over {
		return true, "a command with more words than the check reads"
	}
	// Directories a relative path is also read under (protectedBases). The
	// order of the commands is not followed, so this can add a deny and
	// cannot remove one.
	bases, over := protectedBases(toks, frags, homeAlts, append(append([]string{}, inherited...), work...), prefixes)
	if over {
		return true, "a command with more directories than the check reads"
	}
	if hit, target := shellTokensTouchProtected(toks, prefixes, depth, "", bases); hit {
		return true, target
	}
	for _, base := range bases {
		if hit, target := shellTokensTouchProtected(toks, prefixes, depth, base, bases); hit {
			return true, target
		}
	}

	// A link that `ln` makes in this command to a protected path: the link
	// is not there yet, so a word that goes through it cannot be followed.
	// The command is denied when it does more than make the link and read.
	links, over := linkToProtected(toks, bases, homeAlts, prefixes)
	if over {
		return true, "a command with more links than the check reads"
	}
	if len(links) > 0 && linkIsUsed(cmd, toks, links) {
		return true, "a link to a protected path that the same command can use"
	}
	// The same for an `ln` that stands in a text the command runs: the
	// argument of `SHELL -c`, the words of `eval`, a command substitution.
	if depth == 0 {
		found, over := nestedLinkToProtected(cmd, 0, bases, homeAlts, prefixes)
		if over {
			return true, "a command with more links than the check reads"
		}
		if found && !onlyReadsOrLinks(cmd, 0) {
			return true, "a link to a protected path that the same command can use"
		}
		// A link to another directory, and `..` after its name: the word
		// names the directory above the target of the link. The command is
		// denied when it names a protected path, whether or not it is made
		// of read-only programs: bash reads the word that names the link,
		// and the file the kernel reaches from it is not the file the word
		// spells.
		if found, lnWrites := linkBeforeDotDot(cmd); lnWrites || (found && !onlyReadsOrLinks(cmd, 0)) {
			return true, "a link that the same command makes, with .. after it"
		}
	}

	// A shell call that holds an option of its own which makes the shell run
	// commands (bash -c -i CMD, bash -s, fish -C CM). The text of such a call
	// is a program for the shell and not only an argument: an interactive
	// shell runs the commands it reads, so a call that names a protected path
	// is denied whatever the rest of the call does. The check is made last
	// because every rule above reads the text of the -c through and can give
	// the name of the path itself.
	if shellCommandRunOptionNamesProtected(cmd, prefixes, work) {
		return true, "a shell option that makes the shell run a command naming a protected path"
	}

	// A shell named anywhere in a command that has a pipe or an input
	// redirection may read its commands from there (echo 'rm f' | bash,
	// echo 'rm f' | sh -c 'exec bash'), so the words of the whole command
	// are checked as that input.
	if depth == 0 && strings.ContainsAny(cmd, "|<") && namesShell(frags) {
		if hit, target := stdinShellTouchesProtected(toks, prefixes, depth, bases); hit {
			return true, target
		}
	}

	// (3) A command substitution EXECUTES its inner command for side effects no
	// matter where the captured output goes, so a write hidden inside one —
	// `echo $(rm /protected/f)`, `x=$(rm /protected/f)`, backticks — must be
	// caught even though the output is never used as a path. Recurse into each
	// inner command (depth-bounded). Precise by construction: it fires only when
	// the inner command itself writes to a protected path, so benign
	// `echo $(date)` / `x=$(cat f)` do not fire.
	for _, sub := range extractCommandSubsts(cmd) {
		if depth >= maxShellSubstDepth {
			return true, shortRaw(sub)
		}
		if hit, target := shellTouchesProtectedRec(sub, prefixes, depth+1, bases, nil); hit {
			return true, target
		}
	}

	// The name rule (protect_mention.go): the text names a protected path
	// and the command is not made of read-only programs alone.
	name := commandNamesProtected(toks, frags, bases, work, homeAlts, prefixes)
	unknownDir := false
	if name == "" {
		name = shortRaw(unknownDirWord(cmd, bases))
		unknownDir = name != ""
	}
	if name == "" {
		name = shortRaw(unreadWord(cmd, toks, bases, prefixes))
	}
	if name != "" && !shellOnlyReads(cmd, 0) {
		return true, name
	}
	// A word under a directory the check does not know, in a command that
	// writes with a redirection: the target can be that word under another
	// spelling.
	if unknownDir && strings.ContainsRune(harmlessRedirRe.ReplaceAllString(cmd, ""), '>') {
		return true, name
	}

	return false, ""
}

// shellCommandRunOptionNamesProtected reports whether a call of a shell holds
// an option that makes the shell read commands of its own beyond the text it
// runs (-i, -s, --rcfile, --init-file, fish -i), and whether a text the shell
// runs names a protected path. An interactive shell reads startup files whose
// aliases can change what a program name in the text runs, so such a call is
// denied whatever the text does: bash -c -i 'cat F' is denied, while
// bash -c 'cat F' only reads it. The options are read by parseShellCall, so a
// word after the text of -c is a positional parameter and changes nothing
// (bash -c 'cat F' -i). A call whose options cannot be read is treated the
// same way.
func shellCommandRunOptionNamesProtected(cmd string, prefixes, work []string) bool {
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) < 2 || words[0].unresolved || words[0].raw != words[0].value {
			continue
		}
		if !shellInterpreters[filepath.Base(words[0].value)] {
			continue
		}
		call := parseShellCall(words[0].value, words[1:])
		if call.known && !call.runsInput {
			continue
		}
		for _, arg := range call.commands {
			if commandTextNamesProtected(arg.marked, prefixes, work) {
				return true
			}
		}
	}
	return false
}

// commandTextNamesProtected reports whether the command text names a
// protected path, or a word under a directory the check does not know.
func commandTextNamesProtected(cmd string, prefixes, work []string) bool {
	if runtime.GOOS == "windows" && strings.Contains(cmd, `\`) {
		for _, text := range []string{cmd, decodeWindowsShellEscapes(cmd)} {
			if commandTextNamesProtected(strings.ReplaceAll(text, `\`, "/"), prefixes, work) {
				return true
			}
		}
	}
	toks := tokenizeShell(cmd)
	frags, homeAlts, over := shellFragments(cmd)
	if over {
		return true
	}
	bases, over := protectedBases(toks, frags, homeAlts, work, prefixes)
	if over {
		return true
	}
	if commandNamesProtected(toks, frags, bases, work, homeAlts, prefixes) != "" || unknownDirWord(cmd, bases) != "" || unreadWord(cmd, toks, bases, prefixes) != "" {
		return true
	}
	links, over := linkToProtected(toks, bases, homeAlts, prefixes)
	return over || len(links) > 0
}

// harmlessRedirRe matches a redirection that writes no file: a copy of a
// file descriptor (2>&1) and a redirection to /dev/null.
var harmlessRedirRe = regexp.MustCompile(`[0-9]*[<>]&[0-9-]+|[0-9&]*>>?[ \t]*/dev/null([ \t;|&)]|$)`)

// maxLinkWords bounds the operands of the ln commands that linkToProtected
// reads.
const maxLinkWords = 64

// multiCallPrograms run the program that their first operand names.
var multiCallPrograms = map[string]bool{"busybox": true, "toybox": true}

// linkToProtected returns the segments of the command in which `ln` makes a
// link to a protected path, to something inside one or to a directory above
// one. The link does not exist when the check runs, so a later word that
// goes through it cannot be followed. A relative target of a symbolic link
// is read under the directory of the link, and also as written.
func linkToProtected(toks []shellToken, bases, homeAlts, prefixes []string) (segs map[int]bool, over bool) {
	read := 0
	for n, seg := range splitShellSegments(toks) {
		all := commandWords(seg)
		words := expandBraceWords(stripCommandPrefix(all))
		if len(words) > 1 && !words[0].unresolved && multiCallPrograms[filepath.Base(words[0].value)] {
			words = words[1:] // busybox ln
		}
		// A word before the ln can name the directory it runs in
		// (env -C DIR ln ...).
		var dirs []string
		for _, w := range all {
			if !w.unresolved && filepath.Base(w.value) == "ln" {
				break
			}
			d := stripPathOption(w.value)
			if eq := strings.IndexByte(d, '='); eq >= 0 && strings.HasPrefix(d, "-") {
				d = d[eq+1:] // --chdir=DIR
			}
			if !w.unresolved && d != "" && d[0] != '-' {
				dirs = append(dirs, d)
			}
		}
		// A program that is not read-only can run the words after it as a
		// command: `flock FILE ln ...`, a shell function, "$@".
		if len(words) > 1 && (words[0].unresolved || filepath.Base(words[0].value) != "ln") && !segmentOnlyReads(seg, 0) {
			for i := 0; i < len(words); i++ {
				if !words[i].unresolved && endsInLn(words[i].value) {
					words = words[i:]
					break
				}
			}
		}
		if len(words) == 0 || (words[0].unresolved && !hasSymbolicFlag(words[1:])) || (!words[0].unresolved && !endsInLn(words[0].value)) {
			continue
		}
		// xargs gives ln operands that are not in the text, so the link
		// can be one to a protected path.
		for _, w := range all {
			if !w.unresolved && filepath.Base(w.value) == "xargs" {
				if segs == nil {
					segs = map[int]bool{}
				}
				segs[n] = true
			}
		}
		// A word of the ln that comes from a variable or from a command
		// substitution is not in the text either: ln -s $HOME l.
		for _, w := range words[1:] {
			if w.unresolved {
				if segs == nil {
					segs = map[int]bool{}
				}
				segs[n] = true
			}
		}
		if len(words) < 3 {
			continue
		}
		var ops []string
		afterDashDash := false
		for _, w := range words[1:] {
			v := w.value
			if !afterDashDash && v == "--" {
				afterDashDash = true
				continue
			}
			if !afterDashDash && strings.HasPrefix(v, "-") && stripPathOption(v) == v {
				continue
			}
			op := stripPathOption(v)
			if trimmed := strings.TrimRight(op, "/"); trimmed != "" {
				op = trimmed
			} else if op != "" {
				op = "/" // the root directory is above each path
			}
			ops = append(ops, op)
		}
		if read += len(ops); read > maxLinkWords {
			return nil, true
		}
		for _, target := range ops {
			if target == "" {
				continue
			}
			// Under /dev/fd and /proc a name can stand for a directory
			// that the command opened or works in.
			if clean := stdpath.Clean(target); clean == "/dev" || clean == "/proc" || strings.HasPrefix(clean, "/dev/fd") || strings.HasPrefix(clean, "/proc/") {
				if segs == nil {
					segs = map[int]bool{}
				}
				segs[n] = true
			}
			readings := []string{target}
			if target[0] != '/' && target[0] != '~' {
				// Each other operand can be the link or its directory.
				for _, dest := range ops {
					if dest != "" && dest != target {
						readings = append(readings, stdpath.Dir(dest)+"/"+target, dest+"/"+target)
					}
				}
				for _, dir := range dirs {
					readings = append(readings, dir+"/"+target)
				}
			}
			for _, r := range readings {
				for _, form := range fragmentForms(r, bases, homeAlts) {
					if hit, _ := namesProtected(form, prefixes); hit || isAboveProtected(form, prefixes) {
						if segs == nil {
							segs = map[int]bool{}
						}
						segs[n] = true
					}
				}
			}
		}
	}
	return segs, false
}

// endsInLn reports whether the word is `ln`, a path to it, or a word that
// ends in `!ln` or `=ln` (a git alias: `alias.k=!ln`).
func endsInLn(word string) bool {
	base := filepath.Base(word)
	if cut := strings.LastIndexAny(base, "!="); cut >= 0 {
		base = base[cut+1:]
	}
	return base == "ln"
}

// symbolicFlagRe matches the option of `ln` that asks for a symbolic link.
var symbolicFlagRe = regexp.MustCompile(`^(-[A-Za-z]*s[A-Za-z]*|--symbolic)$`)

// hasSymbolicFlag reports whether a word is the option -s of `ln`. A
// program that is not resolved and has this option is read as `ln`
// (c=ln; $c -s TARGET LINK).
func hasSymbolicFlag(words []shellToken) bool {
	for _, w := range words {
		if !w.unresolved && symbolicFlagRe.MatchString(w.value) {
			return true
		}
	}
	return false
}

// linkIsUsed reports whether the command does more than make the links in
// segs and read: another segment runs a program that is not read-only, a
// redirection writes a file, or a command substitution is not read-only.
func linkIsUsed(cmd string, toks []shellToken, segs map[int]bool) bool {
	if strings.ContainsRune(harmlessRedirRe.ReplaceAllString(cmd, ""), '>') {
		return true
	}
	if shellAnomalyRe.MatchString(homeVarRe.ReplaceAllString(cmd, "~")) || strings.ContainsRune(cmd, '\r') {
		return true
	}
	for n, seg := range splitShellSegments(toks) {
		if !segs[n] && !segmentOnlyReads(seg, 0) {
			return true
		}
	}
	for _, sub := range extractCommandSubsts(cmd) {
		if !shellOnlyReads(sub, 1) {
			return true
		}
	}
	return false
}

// nestedTexts returns the texts that the command runs as commands of their
// own: each command substitution, each argument of `SHELL -c`, and the
// words of `eval`. ok is false when a word of `eval` is not resolved.
func nestedTexts(cmd string) (texts []string, ok bool) {
	ok = true
	texts = append(texts, extractCommandSubsts(cmd)...)
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) < 2 || words[0].unresolved {
			continue
		}
		switch prog := filepath.Base(words[0].value); {
		case shellInterpreters[prog]:
			for _, arg := range parseShellCall(prog, words[1:]).writeCheckTexts() {
				texts = append(texts, arg.marked)
			}
		case prog == "eval":
			parts := make([]string, 0, len(words)-1)
			for _, w := range words[1:] {
				if w.unresolved {
					ok = false
				}
				parts = append(parts, w.value)
			}
			texts = append(texts, strings.Join(parts, " "))
		}
	}
	return texts, ok
}

// assignmentStartRe matches the name and the equals sign of an assignment.
var assignmentStartRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

// possibleTexts returns the texts in the command that a later step can run
// as a command: each word that holds white space (a quoted text, also the
// value of an assignment and a $'...' word), and the words after `echo` or
// `printf`. The check cannot know that a text is run (`eval "$c"`,
// `echo TEXT | bash`), so it reads each one.
func possibleTexts(cmd string, skipData bool) []string {
	var texts []string
	// The command with each escape of a $'...' word as its character.
	if strings.Contains(cmd, "$'") {
		texts = append(texts, decodeAnsiEscapes(strings.ReplaceAll(cmd, "$'", "'")))
	}
	toks := tokenizeShell(cmd)
	for _, seg := range splitShellSegments(toks) {
		if skipData && dataSegment(seg) {
			continue
		}
		for _, t := range seg {
			if t.kind != tokWord {
				continue
			}
			text := unquoteWord(strings.ReplaceAll(t.raw, "$'", "'"))
			if strings.ContainsAny(text, " \t\n") {
				texts = append(texts, assignmentStartRe.ReplaceAllString(text, ""))
			}
		}
	}
	for _, seg := range splitShellSegments(toks) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) < 2 || words[0].unresolved || skipData {
			continue
		}
		if prog := filepath.Base(words[0].value); prog == "echo" || prog == "printf" {
			// An option or a format can stand before the `ln`: the first
			// word of the text is then not a read-only program, and
			// linkToProtected reads the words from the `ln` on.
			parts := make([]string, 0, len(words)-1)
			for _, w := range words[1:] {
				parts = append(parts, w.value)
			}
			texts = append(texts, strings.Join(parts, " "), decodeAnsiEscapes(strings.Join(parts, " ")))
		}
	}
	return texts
}

// ansiLetterRe matches an escape that stands for a white space character.
var ansiLetterRe = regexp.MustCompile(`\\[tnrvf]`)

// decodeAnsiEscapes replaces each \xHH, \uHHHH and octal escape with its
// character, and each \t, \n, \r, \v and \f with a space.
func decodeAnsiEscapes(s string) string {
	return ansiLetterRe.ReplaceAllString(decodeShellEscapes(s), " ")
}

// dataSegment reports whether the command of the segment only prints or
// stores its words: `echo`, `printf`, `git commit` and `git tag`.
func dataSegment(seg []shellToken) bool {
	words := stripCommandPrefix(commandWords(seg))
	if len(words) == 0 || words[0].unresolved {
		return false
	}
	switch filepath.Base(words[0].value) {
	case "echo", "printf":
		return true
	case "git":
		return len(words) > 1 && !words[1].unresolved && (words[1].value == "commit" || words[1].value == "tag")
	}
	return false
}

// textCannotRun reports whether no step of the command can run a text that
// a data segment holds: the command has no pipe, no input redirection, no
// expansion, and names no shell and no `eval`, `source` or `.`.
func textCannotRun(cmd string) bool {
	if strings.ContainsAny(cmd, "|<$`") {
		return false
	}
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		for _, w := range commandWords(seg) {
			if w.unresolved {
				return false
			}
			switch base := filepath.Base(w.value); {
			case shellInterpreters[base], base == "eval", base == "source", base == ".":
				return false
			}
		}
	}
	return true
}

// pathWordRe matches a part of a word that can be a path.
var pathWordRe = regexp.MustCompile(`[^\s'"()=,:;<>|&]+`)

// linkBeforeDotDot reports whether the command makes a link with `ln`,
// another word holds the name of the link, and a word that is not an
// operand of `ln` holds `..` (LINK/../x, and also cd LINK/sub with ../../x
// in a later word). An operand of `ln` that holds `..` after the name of a
// link counts too. The link is not there when the check runs, so the check
// cannot know the directory that `..` names after it.
//
// lnWrites reports that a second `ln` can write through the link: the
// command runs `ln` two times or more, and the place that an `ln` writes
// to can be above the target of the link. Such a command writes with no
// program other than `ln`. A loop and a function are not read-only, so the
// caller denies a command that runs one `ln` in them.
func linkBeforeDotDot(cmd string) (found, lnWrites bool) {
	names := map[string]bool{}
	var words, operands []string
	scan := &lnScan{keys: map[string]bool{}}
	all := linkNamesAndWords(cmd, 0, textCannotRun(cmd), names, &words, &operands, scan)
	if len(names) == 0 {
		return false, false
	}
	many := len(scan.keys) > 1 || scan.fromInput
	if !all {
		return true, many // a link, and more words than the check reads
	}
	isName := func(part string) bool {
		if part == "" || part == "." || part == ".." {
			return false
		}
		if names[part] || names["*"] {
			return true
		}
		if strings.ContainsAny(part, "*?[") {
			for name := range names {
				if ok, _ := stdpath.Match(part, name); ok {
					return true
				}
			}
		}
		return false
	}
	// read reports whether the path holds `..` after the name of a link.
	// It also records a `..` and a name in the path.
	// exact records a name that an operand of ln gives, and not "*".
	dotDot, named, exact := false, false, false
	read := func(p string) (through bool) {
		after := false
		for _, part := range strings.Split(p, "/") {
			switch {
			case part == "..":
				if after {
					through = true
				}
				dotDot = true
			case isName(part):
				after = true
				named = true
				if !names["*"] || names[part] {
					exact = true
				}
			}
		}
		return through
	}
	for _, word := range words {
		// The word as one path (a name can hold a space), and each part
		// of it that can be a path.
		for _, p := range append(pathWordRe.FindAllString(word, -1), word) {
			read(p)
		}
	}
	found = dotDot && named
	// A word names the link: with its name, or with an expansion when
	// the name of the link is not known.
	wordNamed := exact || (named && scan.unresolvedWord)
	// An operand of ln that goes through another link: ln -s l/.. m.
	for _, op := range operands {
		if read(op) {
			found = true
		}
	}
	// The place that an ln writes to holds `..`.
	destDotDot := false
	for _, dest := range scan.dests {
		if strings.Contains(dest, "..") {
			destDotDot = true
		}
	}
	lnWrites = many && (found || (destDotDot && wordNamed))
	return found, lnWrites
}

// lnScan holds what linkNamesAndWords finds about the runs of `ln`.
type lnScan struct {
	// keys has one entry for each `ln` with different words.
	keys map[string]bool
	// dests are the words that name the place an `ln` writes to: the last
	// operand, each operand of an `ln` with -t, and an option with `..`.
	dests []string
	// unresolvedWord is true when a word that is not an operand of `ln`
	// is not resolved.
	unresolvedWord bool
	// fromInput is true when an `ln` has no operand in the command.
	fromInput bool
}

// lnTargetDirRe matches the option of `ln` that names the directory of
// the link (-t, --target-directory).
var lnTargetDirRe = regexp.MustCompile(`^(-[A-Za-su-z]*t|--target-directory)`)

// linkNamesAndWords adds the last part of each operand of each `ln` in the
// command to names, and each other word to words. It reads the texts that
// the command runs or can run in the same way. An operand that is not
// resolved gives the name "*". With skipData, the words of a data segment
// (dataSegment) are not read. all is false when the command holds more
// words than maxLinkNameWords: the names are then complete, and the words
// are not.
func linkNamesAndWords(cmd string, depth int, skipData bool, names map[string]bool, words, operands *[]string, scan *lnScan) (all bool) {
	if depth > maxShellSubstDepth {
		return true // the caller denies a text this deep
	}
	all = true
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		cw := expandBraceWords(stripCommandPrefix(commandWords(seg)))
		at := -1
		for i, w := range cw {
			if !w.unresolved && endsInLn(w.value) && (i == 0 || !segmentOnlyReads(seg, 0)) {
				at = i
				break
			}
		}
		if at < 0 && len(cw) > 0 && cw[0].unresolved && hasSymbolicFlag(cw[1:]) {
			at = 0 // c=ln; $c -s TARGET LINK
		}
		if at >= 0 {
			// The words of this ln, and the place it writes to.
			key := ""
			targetDir := false
			var ops []int
			for i := at + 1; i < len(cw); i++ {
				key += "\x00" + cw[i].value
				switch {
				case !strings.HasPrefix(cw[i].value, "-"):
					ops = append(ops, i)
				case lnTargetDirRe.MatchString(cw[i].value):
					targetDir = true
					fallthrough
				default:
					if strings.Contains(cw[i].value, "..") {
						scan.dests = append(scan.dests, cw[i].value)
					}
				}
			}
			if len(scan.keys) < maxLinkNameWords {
				scan.keys[key] = true
			}
			nOps := len(ops)
			if !targetDir && len(ops) > 1 {
				ops = ops[len(ops)-1:]
			} else if !targetDir {
				ops = nil // ln TARGET writes to the working directory
			}
			for _, i := range ops {
				if len(scan.dests) < maxLinkNameWords {
					scan.dests = append(scan.dests, cw[i].value)
				} else {
					all = false
				}
			}
			if nOps == 0 && !targetDir {
				// xargs ln: the operands come from its input, and the
				// ln can run more than one time.
				names["*"] = true
				scan.unresolvedWord = true
				scan.fromInput = true
			}
		}
		operand := map[string]bool{}
		for i, w := range cw {
			if at < 0 || i <= at || strings.HasPrefix(w.value, "-") {
				continue
			}
			operand[w.value] = true
			if len(*operands) < maxLinkNameWords {
				*operands = append(*operands, w.value)
			} else {
				all = false
			}
			if w.unresolved {
				names["*"] = true
				continue
			}
			if base := stdpath.Base(strings.TrimRight(stripPathOption(w.value), "/")); base != "." && base != "/" && base != ".." {
				names[base] = true
			}
		}
		// Each other word, also the target of a redirection. A word with
		// white space and the words of `echo` and `printf` are texts, and
		// they are read below.
		if raw := commandWords(seg); len(raw) > 0 && !raw[0].unresolved && (raw[0].value == "echo" || raw[0].value == "printf" || (skipData && dataSegment(seg))) {
			for _, w := range raw {
				operand[w.value] = true
			}
		}
		for _, t := range append(append([]shellToken{}, seg...), cw...) {
			if operand[t.value] || looksLikeCommand(t.value) {
				continue
			}
			if t.unresolved {
				scan.unresolvedWord = true
			}
			if len(*words) < maxLinkNameWords {
				*words = append(*words, t.value)
			} else {
				all = false
			}
		}
	}
	texts, _ := nestedTexts(cmd)
	for _, text := range append(texts, possibleTexts(cmd, skipData)...) {
		if !linkNamesAndWords(text, depth+1, false, names, words, operands, scan) {
			all = false
		}
	}
	return all
}

// looksLikeCommand reports whether a word with white space holds a word
// that is `ln`: it is then a text, and it is read as a command.
func looksLikeCommand(word string) bool {
	if !strings.ContainsAny(word, " \t\n") {
		return false
	}
	for _, part := range strings.Fields(word) {
		if endsInLn(part) {
			return true
		}
	}
	return false
}

// maxLinkNameWords bounds the words that linkNamesAndWords collects.
const maxLinkNameWords = 4096

// nestedLinkToProtected reports whether a text that the command runs
// (nestedTexts, at each depth), or can run (possibleTexts), makes a link to
// a protected path with `ln`.
func nestedLinkToProtected(cmd string, depth int, bases, homeAlts, prefixes []string) (found, over bool) {
	if depth >= maxShellSubstDepth {
		return false, false // the caller denies a text this deep
	}
	texts, _ := nestedTexts(cmd)
	texts = append(texts, possibleTexts(cmd, depth == 0 && textCannotRun(cmd))...)
	for _, text := range texts {
		links, over := linkToProtected(tokenizeShell(text), bases, homeAlts, prefixes)
		if over {
			return false, true
		}
		if len(links) > 0 {
			return true, false
		}
		if found, over := nestedLinkToProtected(text, depth+1, bases, homeAlts, prefixes); found || over {
			return found, over
		}
	}
	return false, false
}

// onlyReadsOrLinks reports whether the command, and each text it runs, is
// made of `ln` commands and read-only programs alone, and writes no file
// with a redirection.
func onlyReadsOrLinks(cmd string, depth int) bool {
	if depth > maxShellSubstDepth {
		return false
	}
	if strings.ContainsRune(harmlessRedirRe.ReplaceAllString(cmd, ""), '>') {
		return false
	}
	if shellAnomalyRe.MatchString(homeVarRe.ReplaceAllString(cmd, "~")) || strings.ContainsRune(cmd, '\r') {
		return false
	}
	for _, seg := range splitShellSegments(tokenizeShell(cmd)) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) == 0 {
			continue // an assignment alone; its substitutions are read below
		}
		if words[0].unresolved {
			return false
		}
		prog := filepath.Base(words[0].value)
		if multiCallPrograms[prog] && len(words) > 1 && !words[1].unresolved && filepath.Base(words[1].value) == "ln" {
			continue
		}
		if prog == "ln" || prog == "eval" ||
			(shellInterpreters[prog] && len(parseShellCall(prog, words[1:]).commands) > 0) {
			continue // ln, or a text that is read below
		}
		if !segmentOnlyReads(seg, 0) {
			return false
		}
	}
	texts, ok := nestedTexts(cmd)
	if !ok {
		return false
	}
	for _, text := range texts {
		if !onlyReadsOrLinks(text, depth+1) {
			return false
		}
	}
	return true
}

// namesShell reports whether a fragment is the name of a shell.
func namesShell(frags []string) bool {
	for _, f := range frags {
		if shellInterpreters[filepath.Base(f)] {
			return true
		}
	}
	return false
}

// rebaseWord returns the word as the shell reads it after `cd base`: a
// relative path gets base in front. Absolute paths, tilde paths, options and
// unresolved words are returned as they are. The value of a glued path
// option (`of=REL`, `-tREL`, `--target-directory=REL`) is rebased too.
func rebaseWord(w shellToken, base string) shellToken {
	if base == "" || w.unresolved || w.value == "" {
		return w
	}
	prefix, v := "", w.value
	if stripped := stripPathOption(v); stripped != v {
		prefix, v = v[:len(v)-len(stripped)], stripped
	}
	if v == "" || strings.ContainsRune("/~-+", rune(v[0])) {
		return w
	}
	joined := prefix + strings.TrimRight(base, "/") + "/" + v
	// raw and marked keep their relation to value, which later checks read.
	if w.raw == w.value {
		return shellToken{kind: w.kind, value: joined, raw: joined, marked: joined}
	}
	return shellToken{kind: w.kind, value: joined, raw: w.raw, marked: joined}
}

// writeTargetTouchesProtected checks one word the command writes to as a
// file: a redirection target, or the value of a shell option that names a
// file (fish -o FILE). With base set, a relative word is read under it.
func writeTargetTouchesProtected(t redirTarget, toks []shellToken, prefixes []string, base string, bases []string) (bool, string) {
	if t.unresolved {
		return true, shortRaw(t.raw)
	}
	// bash brace-expands a redirection word too: `> {P,}` and
	// `> settings.{json,}` write P. Every expansion is checked, and a
	// word whose braces cannot be read fails closed.
	for _, w := range expandBraceWords([]shellToken{{kind: tokWord, value: t.value, raw: t.raw, marked: t.value}}) {
		if w.unresolved {
			return true, shortRaw(t.raw)
		}
		value := rebaseWord(w, base).value
		// A target under a directory this check does not know
		// (/proc/self/cwd, /dev/fd/3, /dev/stdin, a ".." under
		// /dev/pts, a link into /proc) can be the protected file.
		if unknownTarget(value, toks) {
			return true, shortRaw(value)
		}
		if hit, target := namesProtected(value, prefixes); hit {
			return true, target
		}
		// The word may hold a list made of parts of the target: with the
		// quotes dropped (`> ''{P,{a}}`) or with a group the comma
		// reader leaves unexpanded (`> {P,{a}}`), the text reaches the
		// shell as one word that can still be the protected path. Each
		// word bash would make from it is read here, quotes kept.
		// Quoting that asks bash for no expansion at all (`> '{P,}'`
		// makes the literal file "{P,}") is left as it is.
		if w.value == t.value {
			for _, alt := range literalBraceAlternatives(t.raw) {
				altT := shellToken{kind: tokWord, value: alt, raw: alt, marked: alt}
				if unknownTarget(alt, toks) {
					return true, shortRaw(alt)
				}
				if hit, target := namesProtected(rebaseWord(altT, base).value, prefixes); hit {
					return true, target
				}
				// A brace word that stays one word also names a path in
				// the part before the list, so the unread-word rule reads
				// it part by part.
				if unreadWord(t.raw, []shellToken{{kind: tokWord, value: t.value, raw: t.raw, marked: t.value}}, bases, prefixes) != "" {
					return true, shortRaw(t.raw)
				}
			}
		}
	}
	// A target under a directory this check does not know fails closed on
	// every reading of the word. A quoted brace is not expanded by bash, so
	// its raw text is checked only when quoting makes no brace list.
	for _, w := range []shellToken{{kind: tokWord, value: t.value, raw: t.raw, marked: t.value}, rebaseWord(shellToken{kind: tokWord, value: t.value, raw: t.raw, marked: t.value}, base)} {
		if unknownTarget(w.value, toks) || (t.raw != t.value && !allBracesQuoted(t.raw) && unknownTarget(w.raw, toks)) {
			return true, shortRaw(w.raw)
		}
	}
	return false, ""
}

// shellTokensTouchProtected is the check of one token stream. With base set,
// every relative path is read under that directory, and the commands a shell
// runs (-c, standard input) are left to the pass without a base.
func shellTokensTouchProtected(toks []shellToken, prefixes []string, depth int, base string, bases []string) (bool, string) {
	// (1) Output-redirection targets.
	seen := map[string]bool{}
	for _, t := range redirectTargets(toks) {
		if seen[t.raw] {
			continue
		}
		seen[t.raw] = true
		if hit, target := writeTargetTouchesProtected(t, toks, prefixes, base, bases); hit {
			return true, target
		}
	}

	// (2) Mutating command carrying a protected path argument. Split into
	// pipeline / list segments so `ls /etc && echo hi` doesn't inherit a
	// mutating verb from a sibling segment.
	for _, seg := range splitShellSegments(toks) {
		words := expandBraceWords(stripCommandPrefix(commandWords(seg)))
		// A shell that reads its commands from standard input
		// (`echo 'rm f' | bash`, `bash <<< 'rm f'`): the text it will run
		// is elsewhere in the command, so every word is checked.
		if base == "" && len(words) > 0 && shellInterpreters[filepath.Base(words[0].value)] && shellReadsStdin(words[0].value, words[1:]) {
			if hit, target := stdinShellTouchesProtected(toks, prefixes, depth, bases); hit {
				return true, target
			}
		}
		if len(words) < 2 {
			continue
		}
		vals := wordValues(words)
		prog := filepath.Base(words[0].value)
		// A shell started with -c runs an argument as a command, so that
		// argument is checked like the command itself. So is the value of a
		// command-bearing option (fish -C, --init-command) and the command
		// glued into such an option after the -c command, which reads as a
		// single word (fish -c 'echo ok' -C'echo x > $X').
		if shellInterpreters[prog] {
			// A file the shell writes because an option names it
			// (fish -o FILE, --profile FILE) is read as a redirection
			// target is: under each base, through links, with its braces.
			for _, f := range parseShellCall(prog, words[1:]).files {
				if hit, target := writeTargetTouchesProtected(redirTarget{value: f.value, raw: f.raw, unresolved: f.unresolved}, toks, prefixes, base, bases); hit {
					return true, target
				}
			}
		}
		if base == "" && shellInterpreters[prog] {
			call := parseShellCall(prog, words[1:])
			for _, arg := range call.writeCheckTexts() {
				if depth >= maxShellSubstDepth {
					return true, shortRaw(arg.raw)
				}
				if hit, target := shellCommandArgTouchesProtected(arg, prefixes, depth+1, bases); hit {
					return true, target
				}
			}
		}
		if base != "" {
			rebased := make([]shellToken, len(words))
			rebased[0] = words[0]
			for i := 1; i < len(words); i++ {
				rebased[i] = rebaseWord(words[i], base)
			}
			words = rebased
			vals = wordValues(words)
		}
		if words[0].unresolved {
			// The program is not known ($CMD ~/.claude). It may be one that
			// changes a directory operand with what is under it.
			for _, w := range words[1:] {
				if !w.unresolved && w.value != "" && w.value[0] != '-' && isAboveProtected(w.value, prefixes) {
					return true, shortRaw(w.raw)
				}
				// The same for a word with $HOME and no other expansion.
				if v, ok := homeVarWord(w); ok && isAboveProtected(v, prefixes) {
					return true, shortRaw(w.raw)
				}
			}
		}
		if !isMutatingProg(prog, vals) {
			continue
		}
		sawDashDash := false
		for _, w := range words[1:] {
			if w.unresolved {
				return true, shortRaw(w.raw)
			}
			if !sawDashDash && w.value == "--" {
				sawDashDash = true
				continue
			}
			// An option token (leading "-", before any "--" separator) is not
			// a path operand: canonicalizing "-rf" against the CWD would
			// fabricate "<cwd>/-rf" and false-positive-deny any mutating
			// command run with flags while the CWD sits inside a protected
			// prefix. Glued path-options ("-t/protected", "-o/dev/sda",
			// --target-directory=/p) still get their embedded path checked
			// below, so skipping the raw flag can only drop fabricated
			// candidates, never a real target. After "--" everything is
			// positional (POSIX), so a file literally named "-rf" is checked.
			optionToken := !sawDashDash && strings.HasPrefix(w.value, "-") && w.value != "-"
			// Match the raw arg and, when it carries a glued path-option prefix
			// (dd of=, cp/mv/ln/install -t / --target-directory=), the path it
			// wraps. Matching both means the strip can only ADD coverage, never
			// hide a plain path.
			if !optionToken {
				if hit, target := matchLiteralPath(w.value, prefixes); hit {
					return true, target
				}
			}
			if !optionToken {
				if hit, target := globTouchesProtected(w.value, ancestorMutatingProgs[prog], prefixes); hit {
					return true, target
				}
			}
			if stripped := stripPathOption(w.value); stripped != w.value {
				if hit, target := matchLiteralPath(stripped, prefixes); hit {
					return true, target
				}
			}
		}
		if hit, target := directoryOperandTouchesProtected(prog, words[1:], prefixes); hit {
			return true, target
		}
	}
	return false, ""
}

// shellPrefixWords are reserved words and the time keyword that may stand
// before a command in a list: `! rm f`, `{ rm f; }`, `if true; then rm f; fi`.
// They are grammar, not programs, so the word after them is the command.
var shellPrefixWords = map[string]bool{
	"!": true, "{": true, "}": true, "if": true, "then": true, "elif": true, "else": true,
	"do": true, "while": true, "until": true, "time": true,
}

// stripCommandPrefix removes leading assignments, reserved words and command
// wrappers (shellWrapperProgs: env, sudo, exec, command, nohup, timeout, ...)
// until the first word is the command name. Only an unquoted word counts as a
// reserved word.
func stripCommandPrefix(words []shellToken) []shellToken {
	for {
		words = stripLeadingAssignments(words)
		if len(words) == 0 || words[0].unresolved {
			return words
		}
		first := words[0].value
		if words[0].raw == first && shellPrefixWords[first] && first != "time" {
			words = words[1:]
			continue
		}
		rest, peeled := unwrapShellWrappers(wordValues(words))
		if !peeled {
			return words
		}
		words = words[len(words)-len(rest):]
	}
}

// shellReadsStdin reports whether a shell started with these arguments reads
// its commands from standard input: it has the -s option, or it has no -c
// command and no script file.
func shellReadsStdin(prog string, args []shellToken) bool {
	c := parseShellCall(prog, args)
	return c.stdin || !c.known
}

// stdinShellTouchesProtected is the check for a command that holds a shell
// reading standard input. A word that names a protected path is a hit, and so
// is a word that touches one when it is read as a command.
func stdinShellTouchesProtected(toks []shellToken, prefixes []string, depth int, bases []string) (bool, string) {
	for _, t := range toks {
		if t.kind != tokWord {
			continue
		}
		if !t.unresolved {
			if hit, target := matchLiteralPath(t.value, prefixes); hit {
				return true, target
			}
		}
		if !strings.ContainsAny(t.value, " \t\n;") {
			continue
		}
		if depth >= maxShellSubstDepth {
			return true, shortRaw(t.raw)
		}
		if hit, target := shellCommandArgTouchesProtected(t, prefixes, depth+1, bases); hit {
			return true, target
		}
	}
	// The arguments of one command, joined, may be the text the shell reads:
	// echo mv ~/.claude ~/x | bash
	if depth >= maxShellSubstDepth {
		return false, ""
	}
	for _, seg := range splitShellSegments(toks) {
		words := commandWords(seg)
		if len(words) < 3 {
			continue
		}
		parts := make([]string, 0, len(words)-1)
		for _, w := range words[1:] {
			parts = append(parts, w.marked)
		}
		joined := strings.Join(parts, " ")
		if hit, target := shellTouchesProtectedRec(joined, prefixes, depth+1, bases, nil); hit {
			return true, strings.ReplaceAll(target, string(rune(shellUnresolvedMark)), "$…")
		}
	}
	return false, ""
}

// maxBraceWords bounds the words one brace expansion may produce.
const maxBraceWords = 64

// expandBraceWords performs the comma form of bash brace expansion on the
// arguments of a command, so `rm ~/.claude/settings.{json,x}` is checked as
// the two paths bash passes to rm. A sequence expression (`{1..3}`) is
// expanded too. A word that holds a quoted or escaped brace, or more
// expansions than maxBraceWords, is marked unresolved, so a path position
// fails closed on it.
func expandBraceWords(words []shellToken) []shellToken {
	needs := false
	for _, w := range words {
		if strings.ContainsRune(w.raw, '{') {
			needs = true
			break
		}
	}
	if !needs {
		return words
	}
	out := make([]shellToken, 0, len(words))
	for _, w := range words {
		if w.unresolved || !strings.ContainsRune(w.raw, '{') {
			out = append(out, w)
			continue
		}
		if w.raw != w.value {
			// Quoting inside the word: which braces are live is not
			// known. bash expands only a brace that carries no quote,
			// so a word whose every brace stands inside quoting is kept
			// as it is (`> '{P,}'` makes the file "{P,}"). A word with
			// a live brace next to a quoted one is not read and fails
			// closed.
			//
			// A live brace is expanded with the quoting kept in mind
			// (`''{P,{a}}` makes P and {a}). A word that holds an expansion
			// as well, or whose list the reader cannot expand, is not read
			// and fails closed.
			if !holdsLiveBrace(w.raw) {
				out = append(out, w)
				continue
			}
			made, ok := expandQuotedBraces(w.raw, maxBraceWords)
			if !ok || strings.ContainsAny(w.raw, "$`") {
				w.unresolved = true
				out = append(out, w)
				continue
			}
			for _, e := range made {
				out = append(out, shellToken{kind: tokWord, value: e, raw: quoteBraces(e), marked: e})
			}
			continue
		}
		expanded, ok := expandBraces(w.value)
		if holdsBraceList(expanded) {
			// expandBraces does not expand a list that holds a brace group
			// of one word (`P.{json,{a}}`, `{P,{a}}`). bash expands the
			// inner group too, so the bounded long expander is asked once.
			// When that too leaves a list, or makes more words than the rule
			// reads, the word stays unresolved and a path position fails
			// closed on it.
			if made, longOK := expandLongBraces(w.value, maxBraceWords); longOK && !holdsBraceList(made) {
				expanded, ok = made, true
			}
		}
		if !ok || holdsBraceList(expanded) {
			w.unresolved = true
			out = append(out, w)
			continue
		}
		for _, e := range expanded {
			out = append(out, shellToken{kind: tokWord, value: e, raw: e, marked: e})
		}
	}
	return out
}

// quoteBraces returns a raw text for a word that bash has already expanded:
// a backslash goes in front of each character the reader would expand again.
func quoteBraces(v string) string {
	if !strings.ContainsAny(v, "{},'\"\\$`") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if strings.IndexByte("{},'\"\\$`", v[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// braceExprRe matches a brace group bash would expand: one with a comma or a
// sequence expression.
var braceExprRe = regexp.MustCompile(`\{[^{}]*(,|\.\.)[^{}]*\}`)

// allBracesQuoted reports whether every "{" and "}" of a word's raw text
// stands inside quoting or after a backslash (quotedChars), so bash expands
// no brace list in it. A word with no brace, or with a quote that does not
// close, returns false.
func allBracesQuoted(raw string) bool {
	if !strings.ContainsAny(raw, "{}") {
		return false
	}
	chars, ok := quotedChars(raw)
	if !ok {
		return false
	}
	for _, q := range chars {
		if (q.c == '{' || q.c == '}') && !q.quoted {
			return false
		}
	}
	return true
}

// expandBraces expands the innermost brace groups of s until none is left.
// ok is false when the result is too large.
func expandBraces(s string) (out []string, ok bool) {
	todo := []string{s}
	for len(todo) > 0 {
		cur := todo[0]
		todo = todo[1:]
		loc := braceExprRe.FindStringIndex(cur)
		if loc == nil {
			out = append(out, cur)
			if len(out) > maxBraceWords {
				return nil, false
			}
			continue
		}
		body := cur[loc[0]+1 : loc[1]-1]
		alts := strings.Split(body, ",")
		if !strings.Contains(body, ",") {
			if alts = braceSequence(body); alts == nil {
				return nil, false
			}
		}
		for _, alt := range alts {
			todo = append(todo, cur[:loc[0]]+alt+cur[loc[1]:])
			if len(todo) > maxBraceWords {
				return nil, false
			}
		}
	}
	return out, true
}

// braceSequence returns the words of a sequence expression: 1..3, 3..1,
// a..e, 1..9..2. It returns nil for another body and for a sequence longer
// than maxBraceWords.
func braceSequence(body string) []string {
	parts := strings.Split(body, "..")
	if len(parts) != 2 && len(parts) != 3 {
		return nil
	}
	step := 1
	if len(parts) == 3 {
		n, err := strconv.Atoi(parts[2])
		if err != nil || n == 0 {
			return nil
		}
		if n < 0 {
			n = -n
		}
		step = n
	}
	from, err1 := strconv.Atoi(parts[0])
	to, err2 := strconv.Atoi(parts[1])
	letters := false
	if err1 != nil || err2 != nil {
		if len(parts[0]) != 1 || len(parts[1]) != 1 {
			return nil
		}
		from, to, letters = int(parts[0][0]), int(parts[1][0]), true
	}
	if from > to {
		step = -step
	}
	var out []string
	for v := from; (step > 0 && v <= to) || (step < 0 && v >= to); v += step {
		if letters {
			out = append(out, string(rune(v)))
		} else {
			out = append(out, strconv.Itoa(v))
		}
		if len(out) > maxBraceWords {
			return nil
		}
	}
	return out
}

// shellInterpreters are programs whose -c argument is a shell command.
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "mksh": true, "rbash": true, "fish": true,
}

// shellCommandArgTouchesProtected checks one word that a shell runs as a
// command. The marked text of the word is tokenized again: each expansion of
// the outer command is a mark there, so an inner word built from one stays
// unresolved inside inner quotes too (bash -c "rm '$HOME/x'"). When the
// program name of an inner command is itself built from an expansion
// (bash -c "$CMD", bash -c $'rm x', bash -c 'X=rm; $X f'), the program is
// unknown and the check fails closed.
func shellCommandArgTouchesProtected(arg shellToken, prefixes []string, depth int, bases []string) (bool, string) {
	inner := arg.marked
	for _, seg := range splitShellSegments(tokenizeShell(inner)) {
		words := stripCommandPrefix(commandWords(seg))
		if len(words) > 0 && words[0].unresolved {
			return true, shortRaw(arg.raw)
		}
	}
	hit, target := shellTouchesProtectedRec(inner, prefixes, depth, bases, nil)
	// The mark is a NUL byte; show it as an expansion in the audit reason.
	return hit, strings.ReplaceAll(target, string(rune(shellUnresolvedMark)), "$…")
}

// homeVarWord returns the word with $HOME as the home directory. ok is false
// when the word does not hold $HOME, or holds another expansion.
func homeVarWord(w shellToken) (value string, ok bool) {
	if !w.unresolved || !homeVarRe.MatchString(w.raw) {
		return "", false
	}
	home, err := shellHomeDir()
	if err != nil || home == "" {
		return "", false
	}
	value = homeVarRe.ReplaceAllLiteralString(unquoteWord(w.raw), home)
	if value == "" || value[0] == '-' || strings.ContainsAny(value, "$`") {
		return "", false
	}
	return value, true
}

// intoDirectoryProgs write a file named after a source operand when another
// operand is a directory: cp settings.json ~/.claude/
var intoDirectoryProgs = map[string]bool{"cp": true, "mv": true, "ln": true, "install": true}

// ancestorMutatingProgs change or remove a directory operand together with
// what is under it: mv ~/.claude ~/.claude-old, chmod 000 ~/.claude
var ancestorMutatingProgs = map[string]bool{
	"rm": true, "mv": true, "rmdir": true, "ln": true,
	"chmod": true, "chown": true, "chgrp": true,
}

// maxPairedOperands is the longest operand list of cp, mv, ln and install in
// which every operand is read as a possible destination.
const maxPairedOperands = 24

// directoryOperandTouchesProtected catches a write that names a directory
// above a protected path in place of the path itself. For cp, mv, ln and
// install it checks every operand joined with the base name of every other
// operand. For the programs in ancestorMutatingProgs it reports an operand
// that is a proper ancestor of a protected path. Both checks can add a deny
// for a command that only reads the directory operand, and cannot remove one.
func directoryOperandTouchesProtected(prog string, args []shellToken, prefixes []string) (bool, string) {
	if !intoDirectoryProgs[prog] && !ancestorMutatingProgs[prog] {
		return false, ""
	}
	var operands []string
	afterDashDash := false
	for _, w := range args {
		v := w.value
		if !afterDashDash && v == "--" {
			afterDashDash = true
			continue
		}
		if !afterDashDash && strings.HasPrefix(v, "-") && v != "-" {
			if stripped := stripPathOption(v); stripped != v {
				operands = append(operands, stripped)
			}
			continue
		}
		operands = append(operands, v)
	}
	if ancestorMutatingProgs[prog] {
		checked := operands
		if prog == "ln" && len(checked) > 1 {
			// ln changes its last operand; the others are link targets.
			checked = checked[len(checked)-1:]
		}
		for _, op := range checked {
			for _, cand := range literalPathCandidates(op) {
				for _, prefix := range prefixes {
					if isProperAncestor(cand, prefix) {
						return true, cand
					}
				}
			}
		}
	}
	if intoDirectoryProgs[prog] {
		// With a long operand list only the operands that can be the
		// destination are joined with the others: the last one, and the
		// value of a target-directory option. Every pair of a long list
		// takes more time than the check has.
		destinations := map[int]bool{}
		if len(operands) > maxPairedOperands {
			destinations[len(operands)-1] = true
			n := 0
			for k, w := range args {
				v := w.value
				isOption := strings.HasPrefix(v, "-") && v != "-"
				if isOption && stripPathOption(v) != v {
					destinations[n] = true // the value glued to the option
				}
				if !isOption || stripPathOption(v) != v {
					if k > 0 && strings.HasPrefix(args[k-1].value, "-") && strings.ContainsRune(args[k-1].value, 't') {
						destinations[n] = true // the word after -t
					}
					n++
				}
			}
		}
		for i, dir := range operands {
			if len(destinations) > 0 && !destinations[i] {
				continue
			}
			if dir == "" || (strings.HasPrefix(dir, "~") && dir != "~" && !strings.HasPrefix(dir, "~/")) {
				continue // matchLiteralPath already failed closed on this tilde form
			}
			for j, src := range operands {
				base := filepath.Base(src)
				if i == j || src == "" || base == "." || base == ".." || base == "/" || base == "~" {
					continue
				}
				joined := strings.TrimRight(dir, "/") + "/" + base
				if hit, target := namesProtected(joined, prefixes); hit {
					return true, target
				}
				// A directory copied or moved to a place above a protected
				// path brings its own files there: cp -r x/.claude ~/
				if isAboveProtected(joined, prefixes) {
					return true, shortRaw(joined)
				}
			}
		}
		// The content of a source directory lands in the destination itself
		// with `SRC/.` or -T: cp -r x/.claude/. ~/.claude
		contentCopy := false
		for _, w := range args {
			v := w.value
			if v == "-T" || v == "--no-target-directory" || (len(v) > 1 && v[0] == '-' && v[1] != '-' && strings.ContainsRune(v, 'T')) {
				contentCopy = true
			}
		}
		for i, op := range operands {
			// "." as the last operand is the destination (cp x .), not a
			// source whose content is copied.
			if strings.HasSuffix(op, "/.") || (op == "." && i < len(operands)-1) {
				contentCopy = true
			}
		}
		if contentCopy {
			for _, op := range operands {
				if hit, target := aboveProtected(op, prefixes); hit {
					return true, target
				}
			}
		}
	}
	return false, ""
}

// aboveProtected reports whether the shell word names a directory above a
// protected path.
func aboveProtected(literal string, prefixes []string) (bool, string) {
	for _, cand := range literalPathCandidates(literal) {
		for _, prefix := range prefixes {
			if isProperAncestor(cand, prefix) {
				return true, cand
			}
		}
	}
	return false, ""
}

// shellHomeDir returns the home directory used by POSIX shell expansion.
func shellHomeDir() (string, error) {
	// POSIX shells use HOME on Windows too. os.UserHomeDir uses
	// USERPROFILE there, which can name a different directory.
	if home := os.Getenv("HOME"); home != "" {
		return filepath.ToSlash(home), nil
	}
	home, err := os.UserHomeDir()
	return filepath.ToSlash(home), err
}

// literalPathCandidates returns the canonical forms of a shell path word,
// including its possible home directories when it starts with a tilde.
func literalPathCandidates(literal string) []string {
	literal = strings.TrimSpace(literal)
	if literal == "" {
		return nil
	}
	if literal == "~" || strings.HasPrefix(literal, "~/") {
		var out []string
		if home, err := shellHomeDir(); err == nil && home != "" {
			out = canonicalCandidates(home + literal[1:])
		}
		// The tool may invoke a native shell whose tilde uses USERPROFILE.
		// Retain this interpretation when HOME points somewhere else.
		if runtime.GOOS == "windows" {
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				out = append(out, canonicalCandidates(home+literal[1:])...)
			}
		}
		return out
	}
	return canonicalCandidates(literal)
}

// bracketExprRe matches one bracket expression of a shell pattern: [abc],
// [!a-c], [^x], []x], [[:alpha:]].
var bracketExprRe = regexp.MustCompile(`\[[!^]?\]?(\[:[a-z]+:\]|[^\]/])*\]`)

// globTouchesProtected checks a word that holds a glob character (*, ?, [).
// It is a hit when the pattern matches a protected path, when its leading
// components match one (the pattern names something inside a protected
// directory), and, with ancestors set, when it matches a directory above a
// protected path (rm -rf ~/.claud*). The match is made one path component at
// a time with path.Match, so * does not cross a slash, as in the shell. A
// "**" component matches any number of components (globstar). Each bracket
// expression is read as "?", which matches every character the expression
// can. Whether a character was quoted is not known here, so every one is
// read as live. Each of these choices can add a deny and cannot remove one.
func globTouchesProtected(literal string, ancestors bool, prefixes []string) (bool, string) {
	if !strings.ContainsAny(literal, "*?[") {
		return false, ""
	}
	pattern := bracketExprRe.ReplaceAllString(literal, "?")
	for _, cand := range literalPathCandidates(pattern) {
		pat := strings.Split(strings.TrimRight(normalizeIfWindowsPath(cand), "/"), "/")
		for _, prefix := range prefixes {
			fold := ignoresCase(prefix)
			for _, p := range canonicalCandidates(prefix) {
				p = strings.TrimRight(normalizeIfWindowsPath(p), "/")
				if globComponentsMatch(pat, strings.Split(p, "/"), ancestors) {
					return true, shortRaw(literal)
				}
				if fold && globComponentsMatch(strings.Split(strings.ToLower(strings.Join(pat, "/")), "/"), strings.Split(strings.ToLower(p), "/"), ancestors) {
					return true, shortRaw(literal)
				}
			}
		}
	}
	// The match above compares text. A pattern can also match a symbolic
	// link (l?nk/x, /proc/self/cw?/x), and then it names what is behind it.
	expansions, over := globLinkExpansions(literal)
	if over {
		return true, shortRaw(literal)
	}
	for _, e := range expansions {
		if hit, _ := matchLiteralPath(e, prefixes); hit {
			return true, shortRaw(literal)
		}
		if ancestors {
			if hit, _ := aboveProtected(e, prefixes); hit {
				return true, shortRaw(literal)
			}
		}
	}
	return false, ""
}

// maxGlobEntries and maxGlobStates bound the directory entries read and the
// paths kept for one pattern in globLinkExpansions.
const (
	maxGlobEntries = 200000
	maxGlobStates  = 20000
)

// globLinkExpansions matches a file name pattern against the file system and
// returns the matches that pass through a symbolic link at or after the first
// pattern part. Text after the last match is kept as written. A match with
// no link in it is left out: the text match of globTouchesProtected reads
// it. Every "*" also matches a name that starts with a dot. over is true
// when the pattern matches more than the bounds allow.
func globLinkExpansions(literal string) (out []string, over bool) {
	literal = strings.TrimSpace(literal)
	if !strings.ContainsAny(literal, "*?[") || len(literal) > maxResolvePathLen {
		return nil, false
	}
	if literal == "~" || strings.HasPrefix(literal, "~/") {
		home, err := shellHomeDir()
		if err != nil || home == "" {
			return nil, false
		}
		literal = filepath.ToSlash(home) + literal[1:]
	}
	if !strings.HasPrefix(literal, "/") {
		if filepath.IsAbs(literal) || strings.HasPrefix(literal, "~") {
			return nil, false
		}
		wd, err := os.Getwd()
		if err != nil {
			return nil, false
		}
		literal = filepath.ToSlash(wd) + "/" + literal
	}
	type state struct {
		path string
		link bool
	}
	states := []state{{}}
	parts := strings.Split(literal, "/")
	last := len(parts) - 1
	for last > 0 && (parts[last] == "" || parts[last] == ".") {
		last--
	}
	entries, sawPattern := 0, false
	for i, part := range parts[:last+1] {
		if part == "" || part == "." {
			continue
		}
		if !strings.ContainsAny(part, "*?[") {
			for k := range states {
				states[k].path += "/" + part
				if sawPattern && part != ".." && !states[k].link {
					if fi, err := os.Lstat(states[k].path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
						states[k].link = true
					}
				}
			}
			continue
		}
		sawPattern = true
		pattern := strings.ReplaceAll(part, "[!", "[^")
		var next []state
		for _, st := range states {
			dir := st.path
			if dir == "" {
				dir = "/"
			}
			list, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			entries += len(list)
			if entries > maxGlobEntries {
				return nil, true
			}
			for _, e := range list {
				if ok, err := stdpath.Match(pattern, e.Name()); err == nil && !ok {
					continue
				}
				link := st.link || e.Type()&os.ModeSymlink != 0
				// A match with no link in it matters only as a directory
				// that the next parts are read in.
				if !link && (i == last || !e.IsDir()) {
					continue
				}
				next = append(next, state{st.path + "/" + e.Name(), link})
				if len(next) > maxGlobStates {
					return nil, true
				}
			}
		}
		states = next
	}
	for _, st := range states {
		if st.link {
			out = append(out, st.path)
		}
	}
	return out, false
}

// globComponentsMatch matches pattern components against the components of
// a protected path. A pattern that is used up first names a directory above
// the path, which counts with ancestors set. A path that is used up first
// means the pattern names something inside it. A component path.Match cannot
// read counts as a match.
func globComponentsMatch(pat, p []string, ancestors bool) bool {
	if len(p) == 0 {
		return true
	}
	if len(pat) == 0 {
		return ancestors
	}
	if pat[0] == "**" {
		return globComponentsMatch(pat[1:], p, ancestors) || globComponentsMatch(pat, p[1:], ancestors)
	}
	if ok, err := path.Match(pat[0], p[0]); err == nil && !ok {
		return false
	}
	return globComponentsMatch(pat[1:], p[1:], ancestors)
}

// isProperAncestor reports whether dir is a directory above the protected
// prefix. Both sides are compared in the form matchPathPrefix uses.
func isProperAncestor(dir, prefix string) bool {
	dir = strings.TrimRight(normalizeIfWindowsPath(dir), "/")
	fold := ignoresCase(prefix)
	for _, p := range canonicalCandidates(prefix) {
		p = strings.TrimRight(normalizeIfWindowsPath(p), "/")
		if len(p) > len(dir) && strings.HasPrefix(p, dir+"/") {
			return true
		}
		if fold && len(p) > len(dir) && strings.HasPrefix(strings.ToLower(p), strings.ToLower(dir)+"/") {
			return true
		}
	}
	return false
}

// matchProtected reports whether the path is a protected path or is inside
// one. Where the file system of the protected path ignores letter case
// (ignoresCase), the two are also compared in lower case.
func matchProtected(cand, prefix string) bool {
	if matchPathPrefix(cand, prefix) {
		return true
	}
	return ignoresCase(prefix) && matchPathPrefix(strings.ToLower(cand), strings.ToLower(prefix))
}

// caseProbe answers ignoresCase for a protected path that is not in the
// cache. A test replaces it.
var caseProbe = fsIgnoresCase

var caseProbeCache = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

// ignoresCase reports whether a path written in another letter case names the
// protected path too. The answer is kept for the life of the process.
func ignoresCase(prefix string) bool {
	caseProbeCache.Lock()
	defer caseProbeCache.Unlock()
	if v, ok := caseProbeCache.m[prefix]; ok {
		return v
	}
	v := caseProbe(prefix)
	caseProbeCache.m[prefix] = v
	return v
}

// fsIgnoresCase is true on macOS and Windows, where the default file system
// ignores letter case. On another system it looks at the deepest directory
// or file of the path that exists and has a letter in its name: when the
// name in the other letter case is the same file, the file system ignores
// case there. A path with no such part gives false.
func fsIgnoresCase(prefix string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return true
	}
	p := prefix
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		p = p[:i]
		p = p[:strings.LastIndex(p, "/")+1]
	}
	p = filepath.Clean(p)
	for len(p) > 1 && p != "." {
		dir, base := filepath.Split(p)
		if swapped := swapLetterCase(base); swapped != base {
			if fi, err := os.Stat(p); err == nil {
				other, err := os.Stat(dir + swapped)
				return err == nil && os.SameFile(fi, other)
			}
		}
		p = filepath.Clean(dir)
	}
	return false
}

// swapLetterCase returns s with every lower-case letter in upper case and
// every upper-case letter in lower case.
func swapLetterCase(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsUpper(r) {
			return unicode.ToLower(r)
		}
		return unicode.ToUpper(r)
	}, s)
}

// mutatingProgs are argv[0] program names that create/modify/delete files.
// sed and dd are handled specially (only mutating with -i / of=).
var mutatingProgs = map[string]bool{
	"rm": true, "cp": true, "mv": true, "tee": true, "truncate": true,
	"ln": true, "install": true, "chmod": true, "chown": true, "chgrp": true,
	"mkdir": true, "rmdir": true, "touch": true, "shred": true,
	"unlink": true, "link": true,
}

func isMutatingProg(prog string, fields []string) bool {
	if mutatingProgs[prog] {
		return true
	}
	switch prog {
	case "sed":
		for _, f := range fields[1:] {
			// -i, -i.bak, -Ei, -ni, --in-place, --in-place=.bak, --in. A single-dash
			// word with an "i" may also be `-e i\\text`-style input glued to
			// its option; reading it as in-place can add a deny only.
			// --i is enough for getopt to read --in-place.
			if strings.HasPrefix(f, "--i") ||
				(strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.ContainsRune(f, 'i')) {
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
	// Tilde. The shell expands a leading "~" before the command runs, so
	// "~/.claude/settings.json" names a file under the home directory. The
	// tokenizer does not tell us whether the tilde was quoted, so every leading
	// tilde is treated as live: that can add a deny and cannot remove one.
	// "~" and "~/x" are checked under the home directory of this process. Any
	// other form ("~user/x", "~+", "~-") names a directory this code cannot
	// know, so the word fails closed like an unresolved variable.
	if strings.HasPrefix(literal, "~") {
		if literal != "~" && !strings.HasPrefix(literal, "~/") {
			return true, shortRaw(literal)
		}
		candidates := literalPathCandidates(literal)
		if len(candidates) == 0 {
			return true, shortRaw(literal)
		}
		for _, cand := range candidates {
			for _, prefix := range prefixes {
				if matchProtected(cand, prefix) {
					return true, cand
				}
			}
		}
	}
	for _, cand := range canonicalCandidates(literal) {
		for _, prefix := range prefixes {
			if matchProtected(cand, prefix) {
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

// volumeNameOf returns the drive or UNC volume at the start of p, reading
// both the separators of the host and the "/"-separated text a POSIX reading
// of a Windows command holds. filepath.VolumeName itself is host-dependent:
// it reads "" in "C:/dir" on a POSIX host and would leave such a path to the
// relative branch, which prepends the working directory.
func volumeNameOf(p string) string {
	if v := filepath.VolumeName(p); v != "" {
		return v
	}
	if v := filepath.VolumeName(filepath.FromSlash(p)); v != "" {
		return v
	}
	// A single letter, a colon and a separator or the end of the text.
	if len(p) >= 2 && p[1] == ':' && isDriveLetter(p[0]) {
		if len(p) == 2 {
			return p
		}
		if p[2] == '/' || p[2] == '\\' {
			return p[:2]
		}
	}
	return ""
}

func isDriveLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
