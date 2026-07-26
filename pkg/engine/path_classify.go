package engine

import (
	stdpath "path"
	"path/filepath"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// evalPathClassify returns true ("rule fires" — i.e. deny) when the
// filesystem path at fields[p.Field] violates any Require predicate.
// Fail-closed semantics on missing field or wrong type.
//
// When ResolveSymlinks is set, the check evaluates BOTH the
// cleaned-only path AND the symlink-resolved path against the prefix
// lists. This covers two distinct bypasses:
//
//  1. Hostile-symlink: text path is /tmp/foo (allowed-looking) but the
//     symlink resolves to /etc/shadow. The resolved form catches it.
//  2. Magic-symlink (/proc/self): text path is /proc/self/environ
//     (matches a /proc/self/ deny prefix) but EvalSymlinks rewrites it
//     to /proc/<pid>/environ which no longer matches. The cleaned
//     form catches it.
//
// Either match denies.
func evalPathClassify(p *domain.PathClassify, fields map[string]interface{}) bool {
	raw, ok := resolveField(p.Field, fields)
	if !ok {
		return true
	}
	path, ok := raw.(string)
	if !ok {
		return true
	}

	// Paths reaching path_classify come from agent tool-call parameters,
	// which are POSIX-style text regardless of what OS this binary runs
	// on (same reasoning as canonicalCandidates in protect.go).
	// filepath.IsAbs alone is not sufficient: on Windows it requires a
	// drive letter and returns false for an already-absolute "/etc/shadow".
	posixAbs := strings.HasPrefix(path, "/")
	if p.Require.AbsoluteOnly && !filepath.IsAbs(path) && !posixAbs {
		return true
	}

	// Shell-meta / control-byte presence: a path containing any of
	// ; & | $ ` \n \t \r \0 is unmistakably an attack signal — no
	// legitimate filename a policy author cares about looks like
	// that. Deny on suspicion before any further normalisation.
	if p.Require.DenyShellMetas && containsShellMeta(path, p.Require.IncludeBackslash) {
		return true
	}

	cleaned := path
	if p.Require.CleanFirst {
		if posixAbs {
			// path.Clean (GOOS-independent), not filepath.Clean: on
			// Windows, filepath.Clean treats a leading "//" as the start
			// of a UNC path and mangles a plain POSIX double-slash input
			// like "//etc//shadow" instead of collapsing it to
			// "/etc/shadow" - path.Clean has no concept of UNC paths at
			// all, sidestepping that ambiguity. See canonicalCandidates
			// in protect.go for the identical fix and full reasoning.
			cleaned = stdpath.Clean(path)
		} else {
			cleaned = filepath.Clean(path)
		}
	}

	if p.Require.MaxPathLength > 0 && len(cleaned) > p.Require.MaxPathLength {
		return true
	}

	// Build the list of variants we'll test against the deny / allow
	// prefix sets. Always test the cleaned (or raw, if CleanFirst is
	// off) form. Optionally add the symlink-resolved form on top.
	variants := []string{cleaned}
	if p.Require.ResolveSymlinks {
		resolved, err := filepath.EvalSymlinks(cleaned)
		if err != nil {
			// When the policy author opted into symlink resolution
			// for write-tool paths, an ENOENT means we cannot
			// confirm the path is safe (attacker may symlink-trample
			// before the tool follows). Fail closed.
			if p.Require.DenyOnResolveFailure {
				return true
			}
		} else if resolved != cleaned {
			variants = append(variants, resolved)
		}
	}

	// Deny: rule fires if ANY variant matches ANY denied prefix.
	for _, v := range variants {
		for _, prefix := range p.Require.DeniedCanonicalPrefixes {
			if matchPathPrefix(v, prefix) {
				return true
			}
		}
	}

	// Allow-list: rule fires unless EVERY variant is under SOME
	// allowed prefix. (Hostile symlink that resolves outside the
	// allowed root fires the rule.)
	if len(p.Require.AllowedCanonicalPrefixes) > 0 {
		for _, v := range variants {
			ok := false
			for _, prefix := range p.Require.AllowedCanonicalPrefixes {
				if matchPathPrefix(v, prefix) {
					ok = true
					break
				}
			}
			if !ok {
				return true
			}
		}
	}

	return false
}

// containsShellMeta returns true if the input string contains any
// shell metacharacter or control byte. Used by DenyShellMetas.
//
// Backslash is gated by includeBackslash because it's a legitimate
// path separator on Windows; flagging it unconditionally would break
// any mixed-platform deployment that mounts Windows file shares.
func containsShellMeta(s string, includeBackslash bool) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '&', '|', '$', '`', '\n', '\r', '\t', 0x00:
			return true
		case '<', '>': // shell redirection
			return true
		case '\\':
			if includeBackslash {
				return true
			}
		}
	}
	return false
}

// matchPathPrefix reports whether path begins with prefix.
//
// Wildcards in prefix:
//
//	"*"  matches exactly one non-empty path component (no /).
//	"**" matches zero or more components, /-spanning, at this position.
//
// Examples:
//
//	"/home/*/.ssh"              matches /home/alice/.ssh, /home/bob/.ssh/id_rsa.
//	"/srv/**/secrets"           matches /srv/team-a/data/secrets, /srv/secrets.
//	"/srv/**/data/*.txt"        not supported; "*" cannot be partial-component.
//
// "*" inside a component (e.g. "*.txt") is NOT supported — the
// wildcard token is the entire component or nothing.
func matchPathPrefix(path, prefix string) bool {
	// Canonicalize Windows-shaped operands to "/"-separated form before
	// comparing. path comes from canonicalCandidates(), which runs
	// filepath.Clean/EvalSymlinks and so is OS-native — on Windows that's
	// "\"-separated. prefix is human-authored policy config, conventionally
	// written with "/" but sometimes authored with "\" on a Windows box.
	// Without this normalization, on Windows path would never match any
	// prefix at all: an allow-list would fail closed on everything (safe
	// but useless), and a deny-list would fail open on everything (silently
	// not firing) — this function backs path_classify, write_classify,
	// shell_classify's argv path lists, and -protect-self/-protect-paths,
	// so a single unnormalized comparison here breaks all four.
	//
	// The normalization is GATED on each operand independently looking like
	// an absolute Windows path (drive letter "C:\..." or UNC "\\server\..."
	// — the only two shapes filepath.Clean ever produces on Windows), not
	// applied unconditionally. An earlier version of this fix did an
	// unconditional strings.ReplaceAll(s, `\`, "/") on both operands, which
	// is a real vulnerability on Unix: "\" IS a legal, if unusual, character
	// in a Unix filename, so a sibling file literally named
	// "documents\secrets.txt" would have its backslash rewritten into a
	// path separator and be misclassified as living INSIDE an allowed
	// "documents/" directory it never actually touches. Gating on the
	// Windows-path shape avoids that: a plain Unix path with a literal "\"
	// in a component name doesn't match the shape and is left untouched.
	//
	// Deliberately not filepath.ToSlash for the runtime candidate either:
	// that's a no-op except when GOOS=windows, so its effect would depend
	// on which platform compiled the binary rather than on the input, and
	// couldn't be exercised by a test running on a non-Windows CI runner.
	path = normalizeIfWindowsPath(path)
	prefix = normalizeIfWindowsPath(prefix)
	if !strings.Contains(prefix, "*") {
		// Common case: literal prefix. Also accept exact match (so
		// "/etc/shadow" matches both /etc/shadow and /etc/shadow/...).
		if path == prefix {
			return true
		}
		if strings.HasPrefix(path, prefix) {
			if strings.HasSuffix(prefix, "/") {
				return true
			}
			if len(path) == len(prefix) || path[len(prefix)] == '/' {
				return true
			}
		}
		return false
	}

	pParts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
	xParts := strings.Split(path, "/")
	return matchSegments(pParts, xParts)
}

// normalizeIfWindowsPath rewrites "\" to "/" only when s itself is shaped
// like an absolute Windows path: drive-letter ("C:\..." or "C:/...") or UNC
// ("\\server\share\..."). Those are the only two absolute-path shapes
// filepath.Clean/EvalSymlinks ever produce on a real Windows build, so this
// check is exact, not a heuristic that could miss a genuine Windows
// candidate. Anything else — including a plain Unix path that happens to
// contain a literal "\" in a component name — is returned unchanged, so a
// real Unix filename's backslash is never mistaken for a path separator.
func normalizeIfWindowsPath(s string) string {
	if isWindowsDriveLetterPath(s) || strings.HasPrefix(s, `\\`) {
		return strings.ReplaceAll(s, `\`, "/")
	}
	return s
}

// isWindowsDriveLetterPath reports whether s starts with a drive letter
// followed by ":" and a separator, e.g. "C:\" or "C:/" — the shape of every
// absolute non-UNC Windows path.
func isWindowsDriveLetterPath(s string) bool {
	if len(s) < 3 {
		return false
	}
	c := s[0]
	isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	return isLetter && s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}

// matchSegments handles "*" (one component) and "**" (zero or more
// components) wildcards by recursive descent. Returns true if pParts
// matches a PREFIX of xParts.
func matchSegments(pParts, xParts []string) bool {
	for i, pp := range pParts {
		if pp == "**" {
			rest := pParts[i+1:]
			if len(rest) == 0 {
				// trailing ** matches everything beneath this point
				return true
			}
			// Try absorbing 0..len(xParts) components into **.
			for k := 0; k <= len(xParts); k++ {
				if matchSegments(rest, xParts[k:]) {
					return true
				}
			}
			return false
		}
		if i >= len(xParts) {
			return false
		}
		if pp == "*" {
			if xParts[i] == "" {
				return false
			}
			continue
		}
		if xParts[i] != pp {
			return false
		}
	}
	return true
}
