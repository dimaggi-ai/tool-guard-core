package engine

import (
	"fmt"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// evalWriteClassifyWithDetail governs a file-writing tool call. Returns (fired,
// reason): fired=true means the write violated a Require predicate (deny). It is a
// COVERAGE rule for the file-write surface; the file tools otherwise pass ungoverned.
// Deny-only: it never rewrites the content.
//
// Path targets are collected from PathField plus the usual file_path/path keys and
// array/nested edit shapes (reusing collectFilePaths), and canonicalized (absolute +
// optional symlink resolution) the same way the protected-path primitive does, so a
// relative or symlinked write is matched.
func evalWriteClassifyWithDetail(w *domain.WriteClassify, fields map[string]interface{}) (bool, string) {
	req := w.Require

	// ── Path predicates ──────────────────────────────────────────────
	if len(req.DeniedPathPrefixes) > 0 || len(req.AllowedPathPrefixes) > 0 {
		targets := collectWriteTargets(w, fields)
		if len(targets) == 0 {
			// A path predicate is set but we can't attribute a path to this write; fail closed.
			// Can't confirm it's inside the allow-list, and can't confirm it's clear of the
			// deny-list.
			return true, "write_classify: a path predicate is set but no write path was found in this call"
		}
		// Canonicalize the prefixes too (absolute + symlink-resolved), exactly like the
		// target paths; otherwise a relative or symlinked prefix fails open. Mirrors
		// protect.go's expandPrefixes.
		denied := expandPrefixes(req.DeniedPathPrefixes)
		allowed := expandPrefixes(req.AllowedPathPrefixes)
		for _, t := range targets {
			cands := canonicalCandidates(t)
			// Denied prefixes: any candidate under any denied prefix fires.
			for _, cand := range cands {
				for _, p := range denied {
					if matchPathPrefix(cand, p) {
						return true, fmt.Sprintf("write_classify: write to %s is under denied prefix %s", cand, p)
					}
				}
			}
			// Allow list: EVERY canonical candidate must independently be under SOME allowed
			// prefix; not just one of them. A write through a symlink that LOOKS like it's
			// inside the allowed root (the lexical candidate matches) but RESOLVES outside it
			// (the symlink-resolved candidate doesn't) must still fire; treating "any candidate
			// matches" as sufficient would let the lexical form satisfy the rule while the
			// resolved form escapes the allow-list entirely. Mirrors path_classify.go's
			// per-variant allow-list loop.
			if len(allowed) > 0 {
				for _, cand := range cands {
					ok := false
					for _, p := range allowed {
						if matchPathPrefix(cand, p) {
							ok = true
							break
						}
					}
					if !ok {
						return true, fmt.Sprintf("write_classify: write to %s is not under any allowed prefix", cand)
					}
				}
			}
		}
	}

	// ── Content predicates ───────────────────────────────────────────
	if req.MaxBytes > 0 || len(req.DeniedContentRegex) > 0 {
		contentStr, ok := writeContent(w, fields)
		if !ok {
			// A content predicate is set but we can't see the bytes being written (wrong type,
			// or no content field present); fail closed.
			return true, "write_classify: a content predicate is set but no readable content field was found in this call"
		}
		if req.MaxBytes > 0 && len(contentStr) > req.MaxBytes {
			return true, fmt.Sprintf("write_classify: content is %d bytes, over the %d-byte cap", len(contentStr), req.MaxBytes)
		}
		for _, pat := range req.DeniedContentRegex {
			re, err := compiledRegex(pat)
			if err != nil {
				return true, fmt.Sprintf("write_classify: denied_content_regex %q did not compile: %v", pat, err)
			}
			if re.MatchString(contentStr) {
				return true, fmt.Sprintf("write_classify: content matches denied pattern %q", pat)
			}
		}
	}

	return false, ""
}

// writeContent returns the bytes being written and whether they were found as a string.
// It reads the configured ContentField, or when none is set, the content-carrying
// fields real coding-agent write tools use (Write.content, Edit.new_string,
// NotebookEdit.new_source, apply_patch.patch, ...). A present but non-string value
// returns ok=false so a content predicate fails closed rather than stringifying an
// object it can't reason about.
func writeContent(w *domain.WriteClassify, fields map[string]interface{}) (string, bool) {
	var keys []string
	if w.ContentField != "" {
		keys = []string{w.ContentField}
	} else {
		for _, k := range []string{"content", "new_string", "new_str", "new_source", "contents", "text", "body", "patch"} {
			keys = append(keys, "parameters."+k)
		}
	}
	for _, k := range keys {
		v, ok := resolveField(k, fields)
		if !ok {
			continue
		}
		switch s := v.(type) {
		case string:
			return s, true
		case []byte:
			return string(s), true
		}
	}
	// A key that was present but non-string falls through to here, as does a call with no
	// content key at all; both force fail-closed (the predicate can't be evaluated on
	// bytes we can't see). A governed write tool is expected to carry its content in one
	// of these fields.
	return "", false
}

// collectWriteTargets gathers write paths from the configured PathField plus standard
// file_path/path/array/nested shapes.
func collectWriteTargets(w *domain.WriteClassify, fields map[string]interface{}) []string {
	var out []string
	if w.PathField != "" {
		if v, ok := resolveField(w.PathField, fields); ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	// Reuse the same extraction as the protected-path primitive (handles file_path/path,
	// string arrays, and one level of nested edit objects).
	if params := parseParamsFromFields(fields); params != nil {
		out = append(out, collectFilePaths(params)...)
	}
	return dedupeStrings(out)
}

// parseParamsFromFields reconstructs a parameters map from flattened "parameters.*"
// fields so collectFilePaths can run. Only top-level parameters keys are needed.
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
