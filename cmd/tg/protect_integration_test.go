//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectIntegrationGeneratedClaudeHook(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(t.TempDir(), "selected profile", "settings.json")
	env := cleanProfileEnvironment(home)
	cmd := exec.Command(tgBinary, "protect", "claude", "-apply", "-config", config, "-tg", tgBinary)
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protect claude: %v\n%s", err, output)
	}
	stateBytes, err := os.ReadFile(config + ".tool-guard-state.json")
	if err != nil {
		t.Fatal(err)
	}
	var state protectState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		t.Fatal(err)
	}

	runInstalled := func(t *testing.T, payload string) hookResultJSON {
		t.Helper()
		cmd := exec.Command(state.Command, state.Args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("installed hook exited nonzero: %v stderr=%s", err, stderr.String())
		}
		var result hookResultJSON
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("decode hook output: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
		return result
	}

	t.Run("destructive delete denied", func(t *testing.T) {
		result := runInstalled(t, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`)
		if result.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("decision=%q, want deny", result.HookSpecificOutput.PermissionDecision)
		}
	})
	t.Run("harmless command allowed", func(t *testing.T) {
		result := runInstalled(t, `{"tool_name":"Bash","tool_input":{"command":"git status"}}`)
		if result.HookSpecificOutput.PermissionDecision != "allow" {
			t.Fatalf("decision=%q, want allow", result.HookSpecificOutput.PermissionDecision)
		}
	})
	t.Run("self configuration write denied", func(t *testing.T) {
		payload := `{"tool_name":"Write","tool_input":{"file_path":` + string(mustJSON(t, config)) + `,"content":"disable"}}`
		result := runInstalled(t, payload)
		if result.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("decision=%q, want deny", result.HookSpecificOutput.PermissionDecision)
		}
	})
	t.Run("consequential tool fails closed", func(t *testing.T) {
		if err := os.WriteFile(state.PolicyPath, []byte("not: [valid"), 0o600); err != nil {
			t.Fatal(err)
		}
		result := runInstalled(t, `{"tool_name":"Bash","tool_input":{"command":"git status"}}`)
		if result.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("decision=%q, want deny", result.HookSpecificOutput.PermissionDecision)
		}
	})
}

func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
