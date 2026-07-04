package engine

import (
	"fmt"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// evalWriteClassifyWithDetail governs a file-writing tool call. Returns
// (fired, reason): fired=true means the write violated a Require predicate
// (deny). It is a COVERAGE rule for the file-write surface — the file tools
// otherwise pass ungoverned. Deny-only: it never rewrites the content.
//
// Path targets are collected from PathField plus the usual file_path/path
// keys and array/nested edit shapes (reusing collectFilePaths), and
// canonicalized (absolute + optional symlink resolution) the same way the
// protected-path primitive does, so a relative or symlinked write is matched.
func evalWriteClassifyWithDetail(w *domain.WriteClassify, fields map[string]interface{}) (bool, string) {
	req := w.Require

	// ── Path predicates ──────────────────────────────────────────────
	targets := collectWriteTargets(w, fields)

	if len(req.DeniedPathPrefixes) > 0 || len(req.AllowedPathPrefixes) > 0 {
		if len(targets) == 0 {
			// A write we can't attribute to a path, but the policy governs
			// paths → fail closed (can't confirm it's inside the allow-list).
			if len(req.AllowedPathPrefixes) > 0 {
				return true, "write_classify: no write path found but allowed_path_prefixes is set"
			}
		}
		for _, t := range targets {
			cands := canonicalCandidates(t)
			if req.ResolveSymlinks {
				// canonicalCandidates already appends the symlink-resolved
				// form; nothing extra needed. (Kept explicit for clarity.)
				_ = cands
			}
			// Denied prefixes: any candidate under any denied prefix fires.
			for _, cand := range cands {
				for _, p := range req.DeniedPathPrefixes {
					if matchPathPrefix(cand, p) {
						return true, fmt.Sprintf("write_classify: write to %s is under denied prefix %s", cand, p)
					}
				}
			}
			// Allow list: EVERY target must be under SOME allowed prefix.
			if len(req.AllowedPathPrefixes) > 0 {
				ok := false
				for _, cand := range cands {
					for _, p := range req.AllowedPathPrefixes {
						if matchPathPrefix(cand, p) {
							ok = true
						}
					}
				}
				if !ok {
					return true, fmt.Sprintf("write_classify: write to %s is not under any allowed prefix", t)
				}
			}
		}
	}

	// ── Content predicates ───────────────────────────────────────────
	contentField := w.ContentField
	if contentField == "" {
		contentField = "parameters.content"
	}
	content, hasContent := resolveField(contentField, fields)
	contentStr := ""
	if hasContent {
		contentStr = fmt.Sprintf("%v", content)
	}

	if req.MaxBytes > 0 && len(contentStr) > req.MaxBytes {
		return true, fmt.Sprintf("write_classify: content is %d bytes, over the %d-byte cap", len(contentStr), req.MaxBytes)
	}

	for _, pat := range req.DeniedContentRegex {
		re, err := compiledRegex(pat)
		if err != nil {
			// A bad pattern must not silently pass; fail closed.
			return true, fmt.Sprintf("write_classify: denied_content_regex %q did not compile: %v", pat, err)
		}
		if re.MatchString(contentStr) {
			return true, fmt.Sprintf("write_classify: content matches denied pattern %q", pat)
		}
	}

	return false, ""
}

// collectWriteTargets gathers the write path(s) from the configured
// PathField plus the standard file_path/path/array/nested shapes.
func collectWriteTargets(w *domain.WriteClassify, fields map[string]interface{}) []string {
	var out []string
	if w.PathField != "" {
		if v, ok := resolveField(w.PathField, fields); ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	// Reuse the same extraction the protected-path primitive uses (handles
	// file_path/path, string arrays, and one level of nested edit objects).
	if params := parseParamsFromFields(fields); params != nil {
		out = append(out, collectFilePaths(params)...)
	}
	return dedupeStrings(out)
}

// parseParamsFromFields reconstructs a parameters map from the flattened
// "parameters.*" fields so collectFilePaths (which walks a params map) can
// run. Only the top-level parameters keys are needed here.
func parseParamsFromFields(fields map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	const pfx = "parameters."
	for k, v := range fields {
		if len(k) > len(pfx) && k[:len(pfx)] == pfx {
			out[k[len(pfx):]] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
