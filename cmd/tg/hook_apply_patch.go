package main

import (
	"encoding/json"
	"fmt"
	"path"
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

// applyPatchText returns the patch text of an apply_patch call. Codex CLI
// 0.166.0 sends it in the parameter command. input and patch are read too.
// A list of strings is joined, one string per line.
func applyPatchText(params map[string]json.RawMessage) string {
	var parts []string
	for _, k := range []string{"command", "input", "patch"} {
		raw, ok := params[k]
		if !ok {
			continue
		}
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
		if !strings.HasPrefix(target, "/") && strings.HasPrefix(cwd, "/") {
			target = path.Join(cwd, target)
		}
		mm := make(map[string]json.RawMessage, len(params)+2)
		for k, v := range params {
			// The patch text is not a shell command. On the key command
			// the engine would read it as one.
			if k != "command" && k != "input" {
				mm[k] = v
			}
		}
		mm["patch"] = patch
		fp, _ := json.Marshal(target)
		mm["file_path"] = fp
		mm["content"] = content
		b, err := json.Marshal(mm)
		if err != nil {
			return nil, "apply_patch parameters could not be encoded", true
		}
		e := *base
		e.Parameters = b
		e.EnvelopeID = fmt.Sprintf("%s-patch-%d", base.EnvelopeID, i+1)
		envs = append(envs, &e)
	}
	return envs, "", true
}
