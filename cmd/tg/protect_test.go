package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func protectFixture(t *testing.T) (home, config, tgPath string, original []byte) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	config = filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	original = []byte("{\n  \"theme\": \"dark\",\n  \"hooks\": {\"PreToolUse\": [{\"matcher\": \"Read\", \"hooks\": [{\"type\": \"command\", \"command\": \"existing-hook\"}]}]}\n}\n")
	if err := os.WriteFile(config, original, 0o640); err != nil {
		t.Fatal(err)
	}
	name := "tg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	tgPath = filepath.Join(home, "bin", name)
	if err := os.MkdirAll(filepath.Dir(tgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tgPath, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home, config, tgPath, original
}

func runProtectTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runProtect(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestProtectClaudeDryRunDoesNotWrite(t *testing.T) {
	_, config, tgPath, original := protectFixture(t)
	code, out, errOut := runProtectTest(t, "claude", "-config", config, "-tg", tgPath)
	if code != 0 {
		t.Fatalf("dry-run code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, `"apply": false`) || !strings.Contains(out, managedAgent) {
		t.Fatalf("dry-run does not show exact managed change: %s", out)
	}
	got, err := os.ReadFile(config)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("dry-run changed config: err=%v got=%s", err, got)
	}
	if _, err := os.Stat(config + ".tool-guard-state.json"); !os.IsNotExist(err) {
		t.Fatalf("dry-run created state: %v", err)
	}
}

func TestProtectClaudeApplyPreservesAndIsIdempotent(t *testing.T) {
	home, config, tgPath, original := protectFixture(t)
	args := []string{"claude", "-apply", "-config", config, "-tg", tgPath}
	code, _, errOut := runProtectTest(t, args...)
	if code != 0 {
		t.Fatalf("apply code=%d stderr=%s", code, errOut)
	}
	installed, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(installed, []byte(`"theme": "dark"`)) || !bytes.Contains(installed, []byte("existing-hook")) {
		t.Fatalf("unrelated settings/hooks lost: %s", installed)
	}
	for _, want := range []string{managedAgent, "-protect-self", "-fail-closed-tools", "bash,write,edit,notebookedit", "-audit-log", `"args"`, `"timeout": 10`} {
		if !bytes.Contains(installed, []byte(want)) {
			t.Errorf("installed command missing %q: %s", want, installed)
		}
	}
	if count := bytes.Count(installed, []byte(managedAgent)); count != 1 {
		t.Fatalf("managed hook count=%d, want 1", count)
	}
	state, err := loadProtectState(config + ".tool-guard-state.json")
	if err != nil {
		t.Fatalf("load protection state: %v", err)
	}
	if filepath.Clean(state.Command) != filepath.Clean(tgPath) {
		t.Fatalf("managed command=%q, want %q", state.Command, tgPath)
	}
	backup, err := os.ReadFile(config + ".tool-guard.bak")
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup is not pristine: err=%v got=%s", err, backup)
	}
	policy := filepath.Join(home, ".config", "tool-guard", "policies", "coding-agent-baseline.yaml")
	if data, err := os.ReadFile(policy); err != nil || !bytes.Contains(data, []byte("deny-recursive-root-delete")) {
		t.Fatalf("starter policy missing/invalid: err=%v data=%s", err, data)
	}
	if info, _ := os.Stat(config); info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode=%o, want 600", info.Mode().Perm())
	}

	code, _, errOut = runProtectTest(t, args...)
	if code != 0 {
		t.Fatalf("repeat apply code=%d stderr=%s", code, errOut)
	}
	repeated, _ := os.ReadFile(config)
	if !bytes.Equal(installed, repeated) {
		t.Fatalf("repeat apply is not idempotent\nfirst=%s\nsecond=%s", installed, repeated)
	}
	backup2, _ := os.ReadFile(config + ".tool-guard.bak")
	if !bytes.Equal(backup2, original) {
		t.Fatal("repeat apply overwrote pristine backup")
	}
}

func TestProtectStatusAndExactUnprotect(t *testing.T) {
	_, config, tgPath, original := protectFixture(t)
	if code, _, errOut := runProtectTest(t, "claude", "-apply", "-config", config, "-tg", tgPath); code != 0 {
		t.Fatal(errOut)
	}
	var statusOut, statusErr bytes.Buffer
	if code := runProtectStatus([]string{"claude", "-config", config}, &statusOut, &statusErr); code != 0 {
		t.Fatalf("status code=%d stderr=%s", code, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), `"protected":true`) || !strings.Contains(statusOut.String(), `"drifted":false`) {
		t.Fatalf("unexpected status: %s", statusOut.String())
	}

	var dryOut, dryErr bytes.Buffer
	if code := runUnprotect([]string{"claude", "-config", config}, &dryOut, &dryErr); code != 0 {
		t.Fatalf("unprotect dry-run: %s", dryErr.String())
	}
	if !strings.Contains(dryOut.String(), `"apply": false`) {
		t.Fatalf("missing unprotect plan: %s", dryOut.String())
	}
	if data, _ := os.ReadFile(config); !bytes.Contains(data, []byte(managedAgent)) {
		t.Fatal("unprotect dry-run removed hook")
	}

	var out, errOut bytes.Buffer
	if code := runUnprotect([]string{"claude", "-apply", "-config", config}, &out, &errOut); code != 0 {
		t.Fatalf("unprotect code=%d stderr=%s", code, errOut.String())
	}
	restored, err := os.ReadFile(config)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("exact restore failed: err=%v got=%s", err, restored)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(config); info.Mode().Perm() != 0o640 {
			t.Fatalf("restored mode=%o, want original 640", info.Mode().Perm())
		}
	}
}

func TestUnprotectPreservesPostInstallDrift(t *testing.T) {
	_, config, tgPath, _ := protectFixture(t)
	if code, _, errOut := runProtectTest(t, "claude", "-apply", "-config", config, "-tg", tgPath); code != 0 {
		t.Fatal(errOut)
	}
	raw, _, root, err := readJSONConfig(config)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	root["post_install_setting"] = "preserve-me"
	drifted, _ := json.MarshalIndent(root, "", "  ")
	if err := os.WriteFile(config, append(drifted, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runUnprotect([]string{"claude", "-apply", "-config", config}, &out, &errOut); code != 0 {
		t.Fatalf("drift unprotect code=%d stderr=%s", code, errOut.String())
	}
	cleaned, _ := os.ReadFile(config)
	if !bytes.Contains(cleaned, []byte("preserve-me")) || bytes.Contains(cleaned, []byte(managedAgent)) {
		t.Fatalf("targeted removal did not preserve drift: %s", cleaned)
	}
}

func TestReprotectAfterDriftCannotDiscardUserChanges(t *testing.T) {
	_, config, tgPath, _ := protectFixture(t)
	args := []string{"claude", "-apply", "-config", config, "-tg", tgPath}
	if code, _, errOut := runProtectTest(t, args...); code != 0 {
		t.Fatal(errOut)
	}
	_, _, root, err := readJSONConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	root["post_install_setting"] = "survives-reprotect"
	drifted, _ := json.MarshalIndent(root, "", "  ")
	if err := os.WriteFile(config, append(drifted, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runProtectTest(t, args...); code != 0 {
		t.Fatalf("reprotect code=%d stderr=%s", code, errOut)
	}
	var out, errOut bytes.Buffer
	if code := runUnprotect([]string{"claude", "-apply", "-config", config}, &out, &errOut); code != 0 {
		t.Fatalf("unprotect code=%d stderr=%s", code, errOut.String())
	}
	cleaned, _ := os.ReadFile(config)
	if !bytes.Contains(cleaned, []byte("survives-reprotect")) || bytes.Contains(cleaned, []byte(managedAgent)) {
		t.Fatalf("reprotect/unprotect discarded drift or kept marker: %s", cleaned)
	}
}

func TestProtectRejectsMissingOrUnsupportedTarget(t *testing.T) {
	for _, args := range [][]string{nil, {"codex"}} {
		code, _, _ := runProtectTest(t, args...)
		if code != 2 {
			t.Fatalf("args=%v code=%d, want 2", args, code)
		}
	}
}

func TestParseClaudeVersion(t *testing.T) {
	tests := []struct {
		version string
		major   int
		minor   int
		patch   int
		ok      bool
	}{
		{version: "2.1.139", major: 2, minor: 1, patch: 139, ok: true},
		{version: "v2.1.220", major: 2, minor: 1, patch: 220, ok: true},
		{version: "2.2.0-beta", major: 2, minor: 2, patch: 0, ok: true},
		{version: "2.1", ok: false},
		{version: "unknown", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			major, minor, patch, err := parseThreePartVersion(tc.version)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, ok=%v", err, tc.ok)
			}
			if tc.ok && (major != tc.major || minor != tc.minor || patch != tc.patch) {
				t.Fatalf("got %d.%d.%d, want %d.%d.%d", major, minor, patch, tc.major, tc.minor, tc.patch)
			}
		})
	}
	if versionLess(2, 1, 138, 2, 1, 139) != true || versionLess(2, 1, 139, 2, 1, 139) != false {
		t.Fatal("minimum-version comparison is incorrect")
	}
}

func TestManagedClaudeHookDetectionSupportsExecAndLegacy(t *testing.T) {
	execForm := map[string]any{
		"command": "/path with spaces/tg",
		"args":    []any{"hook", "-agent-id", managedAgent, "-protect-self"},
	}
	legacy := map[string]any{
		"command": "'/old path/tg' hook -agent-id " + managedAgent + " -protect-self",
	}
	unrelated := map[string]any{
		"command": "/path/tg",
		"args":    []any{"hook", "-agent-id", "another-agent"},
	}
	if !isManagedClaudeHook(execForm) {
		t.Fatal("exec-form managed hook was not recognized")
	}
	if !isManagedClaudeHook(legacy) {
		t.Fatal("legacy shell-form managed hook was not recognized")
	}
	if isManagedClaudeHook(unrelated) {
		t.Fatal("unrelated hook was incorrectly recognized as managed")
	}
}

func TestProtectStatusFailsWhenManagedExecutableDisappears(t *testing.T) {
	_, config, tgPath, _ := protectFixture(t)
	if code, _, errOut := runProtectTest(t, "claude", "-apply", "-config", config, "-tg", tgPath); code != 0 {
		t.Fatalf("protect failed: %s", errOut)
	}
	if err := os.Remove(tgPath); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runProtectStatus([]string{"claude", "-config", config}, &stdout, &stderr); code != 3 {
		t.Fatalf("status code=%d, want 3; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"protected":false`) || !strings.Contains(stdout.String(), `"executable_ok":false`) {
		t.Fatalf("status did not report missing executable: %s", stdout.String())
	}
}
