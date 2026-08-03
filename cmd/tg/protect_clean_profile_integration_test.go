//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const cleanProfileCommandTimeout = 15 * time.Second

type cleanProfileCommandResult struct {
	stdout  []byte
	stderr  []byte
	elapsed time.Duration
}

func TestProtectCleanProfileActivation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "clean profile '$`")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\n  \"theme\": \"clean-profile\",\n  \"unrelated\": {\"preserve\": true}\n}\n")
	if err := os.WriteFile(config, original, 0o640); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(config, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	originalInfo, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}

	env := cleanProfileEnvironment(home)
	statePath := config + ".tool-guard-state.json"
	backupPath := config + ".tool-guard.bak"
	toolGuardHome := filepath.Join(home, ".config", "tool-guard")

	t.Run("protect dry-run writes nothing", func(t *testing.T) {
		result := runCleanProfileTG(t, env, nil,
			"protect", "claude", "-config", config, "-tg", tgBinary)
		var plan protectPlan
		if err := json.Unmarshal(result.stdout, &plan); err != nil {
			t.Fatalf("decode dry-run plan: %v\nstdout=%s\nstderr=%s", err, result.stdout, result.stderr)
		}
		if plan.Apply || !plan.Changed || plan.ConfigPath != config {
			t.Fatalf("unexpected dry-run plan: %+v", plan)
		}
		assertCleanProfilePath(t, home, plan.ConfigPath)
		assertCleanProfilePath(t, home, plan.PolicyPath)
		assertCleanProfilePath(t, home, plan.BackupPath)
		assertFileBytesAndMode(t, config, original, originalInfo.Mode().Perm())
		assertPathAbsent(t, statePath)
		assertPathAbsent(t, backupPath)
		assertPathAbsent(t, toolGuardHome)
	})

	var state protectState
	t.Run("apply and status", func(t *testing.T) {
		result := runCleanProfileTG(t, env, nil,
			"protect", "claude", "-apply", "-config", config, "-tg", tgBinary)
		if result.elapsed >= time.Minute {
			t.Fatalf("activation took %s, want less than one minute", result.elapsed)
		}
		if !bytes.Contains(result.stdout, []byte("protected claude:")) {
			t.Fatalf("unexpected apply output: stdout=%s stderr=%s", result.stdout, result.stderr)
		}

		stateRaw, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatalf("read protection state: %v", err)
		}
		if err := json.Unmarshal(stateRaw, &state); err != nil {
			t.Fatalf("decode protection state: %v", err)
		}
		for _, path := range []string{state.ConfigPath, state.PolicyPath, state.AuditPath, state.BackupPath} {
			assertCleanProfilePath(t, home, path)
		}
		if !strings.Contains(state.PolicyPath, "clean profile") || !strings.Contains(state.AuditPath, "clean profile") {
			t.Fatalf("fixture did not exercise spaces in hook arguments: policy=%q audit=%q", state.PolicyPath, state.AuditPath)
		}
		if !filepath.IsAbs(state.Command) || filepath.Clean(state.Command) != filepath.Clean(tgBinary) {
			t.Fatalf("generated command=%q, want absolute tg path %q", state.Command, tgBinary)
		}
		expectedArgs := []string{
			"hook",
			"-policy", state.PolicyPath,
			"-agent-id", managedAgent,
			"-protect-path", config,
			"-protect-path", state.BackupPath,
			"-protect-path", state.ConfigPath + ".tool-guard-state.json",
			"-protect-path", filepath.Dir(state.AuditPath),
			"-protect-self",
			"-fail-closed-tools", "bash,write,edit,notebookedit",
			"-audit-log", state.AuditPath,
		}
		assertCleanProfileArgs(t, state.Args, expectedArgs)
		assertCleanProfileHandler(t, config, state.Command, state.Args)

		status := runCleanProfileTG(t, env, nil, "status", "claude", "-config", config)
		var got map[string]any
		if err := json.Unmarshal(status.stdout, &got); err != nil {
			t.Fatalf("decode status: %v\nstdout=%s\nstderr=%s", err, status.stdout, status.stderr)
		}
		if got["protected"] != true || got["drifted"] != false {
			t.Fatalf("unexpected protected status: %s", status.stdout)
		}
	})

	t.Run("installed policy denies destructive delete", func(t *testing.T) {
		result := runCleanProfileCommand(t, env,
			[]byte(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`), state.Command, state.Args...)
		assertCleanProfileDecision(t, result, "deny")
	})
	t.Run("installed policy allows harmless command", func(t *testing.T) {
		result := runCleanProfileCommand(t, env,
			[]byte(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`), state.Command, state.Args...)
		assertCleanProfileDecision(t, result, "allow")
	})

	t.Run("unprotect restores exact original", func(t *testing.T) {
		result := runCleanProfileTG(t, env, nil,
			"unprotect", "claude", "-apply", "-config", config)
		if !bytes.Contains(result.stdout, []byte("unprotected claude:")) {
			t.Fatalf("unexpected unprotect output: stdout=%s stderr=%s", result.stdout, result.stderr)
		}
		assertFileBytesAndMode(t, config, original, originalInfo.Mode().Perm())
		assertPathAbsent(t, statePath)
	})
}

func runCleanProfileTG(t *testing.T, env []string, stdin []byte, args ...string) cleanProfileCommandResult {
	t.Helper()
	return runCleanProfileCommand(t, env, stdin, tgBinary, args...)
}

func runCleanProfileCommand(t *testing.T, env []string, stdin []byte, executable string, args ...string) cleanProfileCommandResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cleanProfileCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	err := cmd.Run()
	elapsed := time.Since(started)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s %v exceeded %s; stdout=%s stderr=%s", executable, args, cleanProfileCommandTimeout, stdout.Bytes(), stderr.Bytes())
	}
	if err != nil {
		t.Fatalf("%s %v failed after %s: %v\nstdout=%s\nstderr=%s", executable, args, elapsed, err, stdout.Bytes(), stderr.Bytes())
	}
	return cleanProfileCommandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), elapsed: elapsed}
}

func cleanProfileEnvironment(home string) []string {
	replaced := map[string]bool{
		"HOME": true, "USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true,
		"XDG_CONFIG_HOME": true, "APPDATA": true, "LOCALAPPDATA": true,
	}
	env := make([]string, 0, len(os.Environ())+7)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !replaced[strings.ToUpper(name)] {
			env = append(env, item)
		}
	}
	env = append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
	)
	if volume := filepath.VolumeName(home); volume != "" {
		env = append(env, "HOMEDRIVE="+volume, "HOMEPATH="+strings.TrimPrefix(home, volume))
	}
	return env
}

func assertCleanProfilePath(t *testing.T, home, path string) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatalf("managed path is not absolute: %q", path)
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("managed path escaped clean profile: home=%q path=%q rel=%q err=%v", home, path, rel, err)
	}
}

func assertFileBytesAndMode(t *testing.T, path string, want []byte, wantMode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file bytes changed: path=%s\ngot=%s\nwant=%s", path, got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if gotMode := info.Mode().Perm(); gotMode != wantMode {
			t.Fatalf("file mode changed: path=%s got=%#o want=%#o", path, gotMode, wantMode)
		}
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path unexpectedly exists: %s (stat err=%v)", path, err)
	}
}

func assertCleanProfileDecision(t *testing.T, result cleanProfileCommandResult, want string) {
	t.Helper()
	var got hookResultJSON
	if err := json.Unmarshal(result.stdout, &got); err != nil {
		t.Fatalf("decode hook output: %v\nstdout=%s\nstderr=%s", err, result.stdout, result.stderr)
	}
	if got.HookSpecificOutput.PermissionDecision != want {
		t.Fatalf("permission decision=%q, want %q; stdout=%s stderr=%s",
			got.HookSpecificOutput.PermissionDecision, want, result.stdout, result.stderr)
	}
}

func assertCleanProfileArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("generated args length=%d, want %d\ngot=%q\nwant=%q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("generated args[%d]=%q, want %q\ngot=%q\nwant=%q", i, got[i], want[i], got, want)
		}
	}
}

func assertCleanProfileHandler(t *testing.T, config, command string, args []string) {
	t.Helper()
	var settings struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Type    string   `json:"type"`
					Command string   `json:"command"`
					Args    []string `json:"args"`
					Timeout int      `json:"timeout"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatalf("read protected config: %v", err)
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("decode protected config: %v", err)
	}
	for _, group := range settings.Hooks.PreToolUse {
		for _, hook := range group.Hooks {
			if hook.Command != command {
				continue
			}
			if hook.Type != "command" || hook.Timeout != 10 {
				t.Fatalf("managed handler type=%q timeout=%d, want command/10", hook.Type, hook.Timeout)
			}
			assertCleanProfileArgs(t, hook.Args, args)
			return
		}
	}
	t.Fatalf("managed exec-form handler not found in %s: %s", config, raw)
}
