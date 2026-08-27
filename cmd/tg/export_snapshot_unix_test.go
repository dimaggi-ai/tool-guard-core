//go:build !windows

package main

import (
	"errors"
	"os"
	"testing"
)

func TestAuditSnapshotIsUnlinkedWhileOpen(t *testing.T) {
	snapshot, cleanupDir, err := createAuditSnapshotFile()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if cleanupDir != "" {
		t.Fatalf("Unix snapshot cleanup dir = %q, want none", cleanupDir)
	}
	if _, err := os.Stat(snapshot.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot path remains visible after creation: %v", err)
	}
	if _, err := snapshot.WriteString("sensitive audit bytes"); err != nil {
		t.Fatalf("write unlinked snapshot: %v", err)
	}
}
