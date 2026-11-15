package main

import (
	"os"
	"runtime"
	"testing"
	"time"
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
		// A macOS background service can still be writing under a HOME
		// inside dir when the test ends, so RemoveAll can find a directory
		// that is not empty. Try again for up to 2 s.
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := os.RemoveAll(dir)
			if err == nil {
				return
			}
			if !time.Now().Before(deadline) {
				t.Error(err)
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	return dir
}
