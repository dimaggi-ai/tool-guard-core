package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// maxApplyPatchTargets bounds the number of files one apply_patch call may
// name. A call with more is denied.
const maxApplyPatchTargets = 64

// applyPatchMarkers start the lines of a patch that name a file. The text
// after the marker is the path.
var applyPatchMarkers = []string{
	"*** Add File:",
	"*** Update File:",
	"*** Delete File:",
	"*** Move to:",
}

// applyPatchTextKeys are the normalised parameter names that can carry the
// patch text: command and its aliases (cmd, CommandLine, ...), input, patch
// and the other names a harness has been seen to put a patch under (diff,
// text, body). normaliseHookKey folds case and drops _ - . and space, so
// patch_text and patchText match here too. A harness may act on any of them,
// so all are read.
var applyPatchTextKeys = map[string]bool{
	"input": true, "patch": true, "patchtext": true, "diff": true, "text": true, "body": true,
}

// applyPatchTextKey reports whether a parameter can carry the patch text.
func applyPatchTextKey(k string) bool {
	n := normParamName(k)
	return applyPatchTextKeys[n] || commandAliasNames[n]
}

// applyPatchText returns the patch text of an apply_patch call. Codex CLI
// 0.166.0 sends it in the parameter command. Every key applyPatchTextKey
// accepts is read, in sorted order. A list of strings is joined, one string
// per line.
func applyPatchText(params map[string]json.RawMessage) string {
	var keys []string
	for k := range params {
		if applyPatchTextKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		raw := params[k]
		var s string
		if json.Unmarshal(raw, &s) == nil {
			parts = append(parts, s)
			continue
		}
		var list []string
		if json.Unmarshal(raw, &list) == nil {
			parts = append(parts, list...)
		}
	}
	return strings.Join(parts, "\n")
}

// applyPatchWorkDirKey reports whether a parameter names the directory a
// relative patch path stands in.
func applyPatchWorkDirKey(k string) bool {
	n := normParamName(k)
	return n == "workdir" || n == "workdirectory"
}

// collapseDotParts removes the empty and "." components of a path, which the
// kernel skips, so .claude/./settings.json and .claude//settings.json match a
// policy the way path.Join used to make them match. It keeps "..": the check
// resolves links physically, and popping ".." lexically would hide a link.
func collapseDotParts(p string) string {
	if !strings.Contains(p, "//") && !strings.Contains(p, "/.") && !strings.Contains(p, "./") {
		return p
	}
	parts := strings.Split(p, "/")
	kept := parts[:0:0]
	for i, c := range parts {
		if (c == "" || c == ".") && i > 0 {
			continue
		}
		kept = append(kept, c)
	}
	out := strings.Join(kept, "/")
	if out == "" && strings.HasPrefix(p, "/") {
		out = "/"
	}
	return out
}

// applyPatchTargets returns every path the patch text names and the lines the
// patch adds. Each line that starts with a file marker counts, wherever it
// stands in the text and with any white space before it. The harness applies
// a subset of these lines, so the result can hold a path the patch does not
// write and cannot miss one that it writes.
func applyPatchTargets(text string) (targets []string, added string) {
	seen := map[string]bool{}
	var add []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "+") {
			add = append(add, strings.TrimSuffix(line[1:], "\r"))
			continue
		}
		t := strings.TrimSpace(line)
		for _, m := range applyPatchMarkers {
			if !strings.HasPrefix(t, m) {
				continue
			}
			p := strings.TrimSpace(t[len(m):])
			if !seen[p] {
				seen[p] = true
				targets = append(targets, p)
			}
			break
		}
	}
	return targets, strings.Join(add, "\n")
}

// applyPatchEnvelopes returns one envelope per file an apply_patch call
// names, with the file on file_path and the added lines on content, so the
// protected-path check and the write policies read the call like a call of a
// write tool with a path parameter. A relative path is placed under cwd, the
// working directory the harness reports.
//
// ok is false when the tool is not apply_patch or the text names no file: the
// caller then evaluates the call unchanged. deny is set when the call names
// an empty path or more files than maxApplyPatchTargets.
func applyPatchEnvelopes(base *domain.ActionEnvelope, cwd string) (envs []*domain.ActionEnvelope, deny string, ok bool) {
	if base == nil || base.ToolName != "apply_patch" {
		return nil, "", false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(base.Parameters, &params) != nil {
		return nil, "", false
	}
	// A workdir in the tool input places a relative patch path, as cwd does
	// for the harness call. It is kept only when it is not absolute: the
	// engine already joins a relative parameter named cwd, workdir or
	// workingDir onto the absolute directories of the call, so joining an
	// absolute one here would drop the "workdir" key the engine needs for
	// that and leave the relative directory unseen.
	var relWorkDirs []string
	for _, k := range sortedKeys(params) {
		if applyPatchWorkDirKey(k) {
			var d string
			if json.Unmarshal(params[k], &d) == nil {
				if d = strings.TrimSpace(d); d != "" && !strings.HasPrefix(d, "/") {
					relWorkDirs = append(relWorkDirs, strings.TrimRight(d, "/"))
				}
			}
		}
	}
	text := applyPatchText(params)
	targets, added := applyPatchTargets(text)
	if len(targets) == 0 {
		return nil, "", false
	}
	if len(targets) > maxApplyPatchTargets {
		return nil, fmt.Sprintf("apply_patch names %d files; the hook checks at most %d in one call", len(targets), maxApplyPatchTargets), true
	}
	content, _ := json.Marshal(added)
	patch, _ := json.Marshal(text)
	for i, target := range targets {
		if target == "" {
			return nil, "apply_patch names a file with an empty path", true
		}
		absolute := strings.HasPrefix(target, "/")
		mm := make(map[string]json.RawMessage, len(params)+2)
		for k, v := range params {
			// The patch text is not a shell command. On the key command
			// the engine would read it as one.
			if !applyPatchTextKey(k) {
				mm[k] = v
			}
		}
		mm["patch"] = patch
		mm["content"] = content
		dirs := []string{""}
		if !absolute {
			if strings.HasPrefix(cwd, "/") {
				dirs = append(dirs, strings.TrimRight(cwd, "/"))
			}
			for _, wd := range relWorkDirs {
				if strings.HasPrefix(cwd, "/") {
					// Absolute, so the engine joins the bare target onto it.
					dirs = append(dirs, strings.TrimRight(cwd, "/")+"/"+wd)
				}
				dirs = append(dirs, wd)
			}
		}
		for j, d := range dirs {
			// Not path.Join: it removes "link/.." lexically, and the kernel
			// follows the link first. The check resolves links itself.
			full := collapseDotParts(d + "/" + target)
			if full == "" {
				full = "."
			}
			fp, _ := json.Marshal(full)
			mm["file_path"] = fp
			b, err := json.Marshal(mm)
			if err != nil {
				return nil, "apply_patch parameters could not be encoded", true
			}
			e := *base
			e.Parameters = b
			e.EnvelopeID = fmt.Sprintf("%s-patch-%d-%d", base.EnvelopeID, i+1, j+1)
			envs = append(envs, &e)
		}
	}
	return envs, "", true
}

// sortedKeys returns the keys of params in order, so the envelopes built from
// them do not depend on map iteration order.
func sortedKeys(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
