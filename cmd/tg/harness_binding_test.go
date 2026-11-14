package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHarnessReleaseBinding(t *testing.T) {
	for _, tool := range []string{"python3", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("release binding integration test needs %s: %v", tool, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", filepath.Join("..", "..", "scripts", "test_check_harness_evidence.py"), "-v")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release binding regression suite: %v\n%s", err, out)
	}
}
