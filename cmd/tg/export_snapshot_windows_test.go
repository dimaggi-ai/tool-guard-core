//go:build windows

package main

import (
	"errors"
	"os"
	"testing"
)

func TestAuditSnapshotUsesDeleteOnClose(t *testing.T) {
	snapshot, cleanupDir, err := createAuditSnapshotFile()
	if err != nil {
		t.Fatal(err)
	}
	name := snapshot.Name()
	if cleanupDir == "" {
		t.Fatal("Windows snapshot has no private cleanup directory")
	}
	if _, err := snapshot.WriteString("sensitive audit bytes"); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("close delete-on-close snapshot: %v", err)
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot still exists after close: %v", err)
	}
	if err := os.Remove(cleanupDir); err != nil {
		t.Fatalf("remove empty snapshot directory: %v", err)
	}
}
