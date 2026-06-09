package engine

import (
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

	if p.Require.AbsoluteOnly && !filepath.IsAbs(path) {
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
		cleaned = filepath.Clean(path)
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
