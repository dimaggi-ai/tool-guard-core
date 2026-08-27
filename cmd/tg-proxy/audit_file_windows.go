//go:build windows

package main

import (
	"fmt"
	"os"
)

// Windows opens O_APPEND files with FILE_APPEND_DATA rather than
// GENERIC_WRITE, so File.Truncate on the append handle returns access denied.
// Open a short-lived write handle to the same file, prove its identity, and
// truncate through that handle while retaining atomic append semantics on the
// long-lived writer.
func (f *diskAuditLog) Truncate(size int64) error {
	originalInfo, err := f.File.Stat()
	if err != nil {
		return fmt.Errorf("stat open audit handle: %w", err)
	}
	rollback, err := os.OpenFile(f.path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open rollback handle: %w", err)
	}
	defer rollback.Close()
	rollbackInfo, err := rollback.Stat()
	if err != nil {
		return fmt.Errorf("stat rollback handle: %w", err)
	}
	if !os.SameFile(originalInfo, rollbackInfo) {
		return fmt.Errorf("rollback path no longer identifies the open audit file")
	}
	if err := rollback.Truncate(size); err != nil {
		return err
	}
	// Flush through the handle that performed the metadata change. The caller
	// also syncs the long-lived append handle before verifying the final size.
	if err := rollback.Sync(); err != nil {
		return fmt.Errorf("sync rollback handle: %w", err)
	}
	return nil
}
