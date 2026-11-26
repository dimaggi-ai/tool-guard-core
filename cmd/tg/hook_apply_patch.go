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
// accepts is read, in sorted order. So is every other string in the tool
// input, at any depth in objects and lists, that holds a file marker: a
// harness may put the patch under a key this list does not know (changes,
// args, input.patch). A list of strings is joined, one string per line.
// deep is true when a value nested deeper than maxPatchValueDepth holds a
// file marker: the caller denies the call, as its files are not read.
func applyPatchText(params map[string]json.RawMessage) (text string, deep bool) {
	var parts []string
	for _, k := range sortedKeys(params) {
		if applyPatchTextKey(k) {
			var s string
			if json.Unmarshal(params[k], &s) == nil {
				parts = append(parts, s)
				continue
			}
			var list []string
			if json.Unmarshal(params[k], &list) == nil {
				parts = append(parts, list...)
				continue
			}
		}
		parts = append(parts, patchStrings(params[k], 0, &deep)...)
	}
	return strings.Join(parts, "\n"), deep
}

// maxPatchValueDepth bounds how deep patchStrings reads nested values.
const maxPatchValueDepth = 16

// patchStrings returns the strings in a JSON value that hold a file marker.
// A list of strings that holds one is returned whole, one string per line.
// A value nested deeper than maxPatchValueDepth is not read: deep is set
// when its JSON text holds a marker.
func patchStrings(raw json.RawMessage, depth int, deep *bool) []string {
	if depth > maxPatchValueDepth {
		if holdsPatchMarker(string(raw)) {
			*deep = true
		}
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if holdsPatchMarker(s) {
			return []string{s}
		}
		return nil
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		if holdsPatchMarker(strings.Join(strs, "\n")) {
			return strs
		}
		return nil
	}
	var out []string
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		for _, v := range list {
			out = append(out, patchStrings(v, depth+1, deep)...)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, k := range sortedKeys(obj) {
			out = append(out, patchStrings(obj[k], depth+1, deep)...)
		}
	}
	return out
}

// holdsPatchMarker reports whether a text holds a file marker of a patch.
func holdsPatchMarker(s string) bool {
	for _, m := range applyPatchMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// applyPatchWorkDirKeys are the normalised parameter names that can name the
// directory a relative patch path stands in. dir, directory, root and path
// are read too: a harness may use one of them, and a directory read in
// excess can only add a deny.
var applyPatchWorkDirKeys = map[string]bool{
	"workdir": true, "workdirectory": true, "workingdir": true, "workingdirectory": true, "cwd": true,
	"dir": true, "directory": true, "root": true, "path": true,
}

// patchWorkDirs returns the string values of the work directory keys in a
// JSON object, at any depth up to maxPatchValueDepth in objects and lists
// (input.workdir, args.cwd). deep is set when a value is nested deeper.
func patchWorkDirs(params map[string]json.RawMessage, depth int, deep *bool) []string {
	var out []string
	for _, k := range sortedKeys(params) {
		raw := params[k]
		if applyPatchWorkDirKey(k) {
			var d string
			if json.Unmarshal(raw, &d) == nil {
				if d = strings.TrimSpace(d); d != "" {
					if t := strings.TrimRight(d, "/"); t != "" {
						d = t
					}
					out = append(out, d)
				}
				continue
			}
		}
		out = append(out, patchWorkDirsIn(raw, depth+1, deep)...)
	}
	return out
}

func patchWorkDirsIn(raw json.RawMessage, depth int, deep *bool) []string {
	if len(raw) == 0 || (raw[0] != '{' && raw[0] != '[') {
		return nil
	}
	if depth > maxPatchValueDepth {
		*deep = true
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		return patchWorkDirs(obj, depth, deep)
	}
	var list []json.RawMessage
	var out []string
	if json.Unmarshal(raw, &list) == nil {
		for _, v := range list {
			out = append(out, patchWorkDirsIn(v, depth+1, deep)...)
		}
	}
	return out
}

// applyPatchWorkDirKey reports whether a parameter names the directory a
// relative patch path stands in: workdir, working_dir, working_directory,
// cwd, workingDir, work_dir and the other spellings normParamName folds.
func applyPatchWorkDirKey(k string) bool {
	return applyPatchWorkDirKeys[normParamName(k)]
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
	// A work directory in the tool input places a relative patch path, as
	// cwd does for the harness call. An absolute one is used as it is. A
	// relative one is placed under cwd and is also kept as it is. It can
	// stand next to a nested patch (input.workdir with input.patch).
	text, deep := applyPatchText(params)
	if deep {
		return nil, fmt.Sprintf("apply_patch holds a patch nested deeper than %d levels; the hook does not read it", maxPatchValueDepth), true
	}
	targets, added := applyPatchTargets(text)
	if len(targets) == 0 {
		return nil, "", false
	}
	workDirs := patchWorkDirs(params, 0, &deep)
	if deep {
		return nil, fmt.Sprintf("apply_patch holds a value nested deeper than %d levels; the hook does not read it", maxPatchValueDepth), true
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
		// "" stands for the target as the patch spells it: a relative
		// target stays relative, and is not placed under the root.
		dirs := []string{""}
		if !absolute {
			if strings.HasPrefix(cwd, "/") {
				dirs = append(dirs, strings.TrimRight(cwd, "/"))
			}
			for _, wd := range workDirs {
				if !strings.HasPrefix(wd, "/") && strings.HasPrefix(cwd, "/") {
					dirs = append(dirs, strings.TrimRight(cwd, "/")+"/"+wd)
				}
				dirs = append(dirs, wd)
			}
		}
		for j, d := range dirs {
			// Not path.Join: it removes "link/.." lexically, and the kernel
			// follows the link first. The check resolves links itself.
			full := target
			if d != "" {
				full = strings.TrimSuffix(d, "/") + "/" + target
			}
			full = collapseDotParts(full)
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
