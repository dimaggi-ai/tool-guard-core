package main

import (
	"os"
	"runtime"
	"testing"
)

// exampleWorkspaceTempDir keeps allow controls outside the shipped policy's
// /var deny prefix. macOS normally puts t.TempDir under /var/folders.
func exampleWorkspaceTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/tmp", "tg-example-workspace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
