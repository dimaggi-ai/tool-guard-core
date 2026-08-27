//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAPI_IgnoresGoRunDiagnosticsOnSuccess(t *testing.T) {
	output, err := runCheckAPIWithFakeGo(t, `#!/bin/sh
echo 'go: downloading a pinned tool dependency' >&2
exit 0
`)
	if err != nil {
		t.Fatalf("check-api rejected harmless go diagnostics: %v\n%s", err, output)
	}
	if !strings.Contains(output, "OK: exported Go API matches") {
		t.Fatalf("success output missing confirmation: %s", output)
	}
}

func TestCheckAPI_StillRejectsAPIDiffOnStdout(t *testing.T) {
	output, err := runCheckAPIWithFakeGo(t, `#!/bin/sh
echo 'go: downloading a pinned tool dependency' >&2
echo 'pkg domain: incompatible change'
exit 0
`)
	if err == nil {
		t.Fatalf("check-api accepted an API diff: %s", output)
	}
	if !strings.Contains(output, "incompatible change") {
		t.Fatalf("failure output omitted API diff: %s", output)
	}
}

func TestCheckAPI_ReportsToolFailureDiagnostics(t *testing.T) {
	output, err := runCheckAPIWithFakeGo(t, `#!/bin/sh
echo 'apidiff failed to load the module' >&2
exit 1
`)
	if err == nil {
		t.Fatalf("check-api accepted a failed apidiff command: %s", output)
	}
	if !strings.Contains(output, "apidiff failed to load the module") {
		t.Fatalf("failure output omitted tool diagnostics: %s", output)
	}
}

func runCheckAPIWithFakeGo(t *testing.T, fakeGo string) (string, error) {
	t.Helper()
	binDir := t.TempDir()
	goPath := filepath.Join(binDir, "go")
	if err := os.WriteFile(goPath, []byte(fakeGo), 0o700); err != nil {
		t.Fatalf("write fake go command: %v", err)
	}
	cmd := exec.Command("bash", filepath.Join("..", "..", "scripts", "check-api.sh"))
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	combined, err := cmd.CombinedOutput()
	return string(combined), err
}
