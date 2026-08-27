//go:build !windows

package main

import "os"

func createAuditSnapshotFile() (*os.File, string, error) {
	snapshot, err := os.CreateTemp("", "toolguard-audit-export-*")
	if err != nil {
		return nil, "", err
	}
	// Unlink immediately: the open descriptor remains readable, but a crash or
	// forced termination cannot leave sensitive audit bytes in the temp dir.
	if err := os.Remove(snapshot.Name()); err != nil {
		_ = snapshot.Close()
		_ = os.Remove(snapshot.Name())
		return nil, "", err
	}
	return snapshot, "", nil
}
