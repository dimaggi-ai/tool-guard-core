//go:build !windows

package main

import "os"

func renameAuditFile(from, to string) error {
	return os.Rename(from, to)
}

// syncAuditDirectory makes the rename and creation of the replacement active
// file crash-durable on filesystems that implement directory fsync.
func syncAuditDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
