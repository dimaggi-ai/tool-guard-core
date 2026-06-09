package engine

import (
	"path/filepath"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// evalShellClassify returns true (deny) when the argv list at
// fields[s.Field] violates any Require predicate. The field MUST
// resolve to an array of strings (a JSON []string). Free-text strings
// are rejected outright — the whole point of shell_classify is that
// the tool already split the command into argv and will exec the
// program directly, no shell involved.
func evalShellClassify(s *domain.ShellClassify, fields map[string]interface{}) bool {
	raw, ok := resolveField(s.Field, fields)
	if !ok {
		return true
	}

	argv, ok := normalizeArgv(raw)
	if !ok || len(argv) == 0 {
		return true
	}

	if s.Require.MaxArgc > 0 && len(argv) > s.Require.MaxArgc {
		return true
	}

	if len(s.Require.Argv0Allowlist) > 0 {
		head := argv[0]
		// Accept either a bare program name or a full path; compare
		// the basename only.
		head = filepath.Base(head)
		permitted := false
		for _, allow := range s.Require.Argv0Allowlist {
			if head == allow {
				permitted = true
				break
			}
		}
		if !permitted {
			return true
		}
	}

	if len(s.Require.ArgvDenyPatterns) > 0 {
		for _, pat := range s.Require.ArgvDenyPatterns {
			re, err := compiledRegex(pat)
			if err != nil {
				// Bad pattern → fail closed for this rule.
				// ValidatePolicy + PrewarmRegexCache populate the
				// cache at load so this branch is now reachable
				// only when a hot reload swapped in a bad pattern
				// past validation (shouldn't happen).
				return true
			}
			for _, arg := range argv {
				if re.MatchString(arg) {
					return true
				}
			}
		}
	}

	if len(s.Require.DeniedArgvPaths) > 0 {
		for _, arg := range argv {
			if !filepath.IsAbs(arg) {
				continue
			}
			cleaned := filepath.Clean(arg)
			// Test cleaned form and (when configured) the symlink-
			// resolved form. Either match denies.
			variants := []string{cleaned}
			if s.Require.ResolveSymlinks {
				if resolved, err := filepath.EvalSymlinks(cleaned); err == nil && resolved != cleaned {
					variants = append(variants, resolved)
				}
			}
			for _, v := range variants {
				for _, prefix := range s.Require.DeniedArgvPaths {
					if matchPathPrefix(v, prefix) {
						return true
					}
				}
			}
		}
	}

	// argv[0]=env|sudo|nice|ionice can smuggle env-var settings as
	// argv[1+] like "BASH_FUNC_x%%=() { evil; }". When the policy
	// supplies a deny pattern, scan every arg AFTER argv[0] for it.
	if s.Require.ArgvEnvPatternDeny != "" && len(argv) > 1 {
		head := filepath.Base(argv[0])
		switch head {
		case "env", "sudo", "nice", "ionice", "chroot", "doas":
			re, err := compiledRegex(s.Require.ArgvEnvPatternDeny)
			if err != nil {
				return true // fail closed on bad pattern
			}
			for _, arg := range argv[1:] {
				if re.MatchString(arg) {
					return true
				}
			}
		}
	}

	return false
}

// normalizeArgv accepts the value resolved from fields and converts
// to a flat []string. Accepts either []any or []string. A single
// string (the dangerous case — caller passed a shell command) is
// rejected: shell_classify exists specifically to refuse free-text.
func normalizeArgv(v interface{}) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				// Non-string element (number, bool, object) — refuse.
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// DangerousMetacharRegex is a default-recommended ArgvDenyPatterns
// element for policy authors who want to deny shell metacharacters in
// argv arguments. Not auto-applied — policies must list it explicitly
// under shell_classify.require.argv_deny_patterns.
//
// Pattern covers: ; & | ` $ (metacharacters); $( command
// substitution; ${ variable expansion; >> << < > redirection.
var DangerousMetacharRegex = strings.Join([]string{
	"[;&|`$]",
	`\$\(`,
	`\${`,
	`>>`, `<<`, `<`, `>`,
}, "|")
