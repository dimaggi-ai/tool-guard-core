package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookReview73PatchCommandList(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: plain.txt\n+x\n*** End Patch"
	args := []string{"-policy-dir", filepath.Join("..", "..", "policies"), "-mode", "enforcement", "-dialect", "claude", "-escalate-as", "deny", "-fail-closed-tools", "bash,powershell,write,edit,notebookedit", "-fail-closed-groups", "shell,filesystem_writes,network_egress"}
	for _, tc := range []struct {
		name    string
		command any
		want    string
	}{
		{"strings", []any{"apply_patch", patch}, "allow"},
		{"null element", []any{patch, nil}, "deny"},
		{"number element", []any{patch, 7}, "deny"},
		{"object element", []any{patch, map[string]any{}}, "deny"},
		{"nested list", []any{patch, []string{"x"}}, "deny"},
		{"null command", nil, "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, reason := applyPatchDecision(t, args, map[string]any{"command": tc.command}, "/w")
			if dec != tc.want {
				t.Fatalf("got %s (%s), want %s", dec, reason, tc.want)
			}
			if tc.want == "deny" && !strings.Contains(reason, "not a string") {
				t.Fatalf("expected malformed-input denial: %s", reason)
			}
		})
	}
	for _, tool := range []string{"bash", "write_file"} {
		payload, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": map[string]any{"command": []string{patch}}})
		out, _ := runHookStr(t, string(payload), args...)
		dec, reason := hookDecisionReason(t, out)
		if dec != "deny" || !strings.Contains(reason, "not a string") {
			t.Fatalf("%s: %s", tool, out)
		}
	}
}

func TestHookReview73PatchCommandListWrapper(t *testing.T) {
	for _, tc := range []struct{ name, target, want string }{
		{"plain", "plain.txt", "allow"},
		{"protected", ".codex/hooks.json", "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			target := tc.target
			if tc.want == "deny" {
				target = filepath.ToSlash(filepath.Join(home, tc.target))
			}
			patch := "*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch"
			payload, _ := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": "/w", "tool_input": map[string]any{"command": []string{"apply_patch", patch}}})
			out := runExampleHook(t, filepath.Join(exampleDir(t), "hooks", "codex-hook.sh"), home, string(payload))
			dec, _ := exampleDecision(t, out)
			if dec != tc.want {
				t.Fatalf("got %s, want %s: %s", dec, tc.want, out)
			}
		})
	}
}

func TestHookReview73EscapeEquivalentAliases(t *testing.T) {
	for _, family := range []string{"file_path", "content", "command"} {
		t.Run(family, func(t *testing.T) {
			fields := []string{fmt.Sprintf("%q:%q", family, "plain.txt")}
			for i := 0; i < 18; i++ {
				var value strings.Builder
				for j, r := range "plain.txt" {
					if i&(1<<j) != 0 {
						fmt.Fprintf(&value, `\u%04x`, r)
					} else {
						value.WriteRune(r)
					}
				}
				fields = append(fields, fmt.Sprintf(`%q:"%s"`, strings.Repeat("_", i+1)+family, value.String()))
			}
			raw := "{" + strings.Join(fields, ",") + "}"
			variants, truncated := hookParamVariants(json.RawMessage(raw))
			if truncated || len(variants) != 0 {
				t.Fatalf("identical decoded values: %d variants, truncated=%v", len(variants), truncated)
			}
			payload := `{"tool_name":"Write","tool_input":` + raw + `}`
			out, _ := runHookStr(t, payload, "-policy", filepath.Join("..", "..", "policies", "coding_agent_context_files.yaml"), "-mode", "enforcement", "-fail-closed-groups", "shell,filesystem_writes,network_egress")
			dec, _ := hookDecisionReason(t, out)
			if dec != "allow" {
				t.Fatalf("equivalent aliases: %s", out)
			}
		})
	}
}
