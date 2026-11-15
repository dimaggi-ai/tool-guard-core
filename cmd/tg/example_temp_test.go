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
		var err error
		for i := 0; i < 10; i++ {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Error(err)
	})
	return dir
}
