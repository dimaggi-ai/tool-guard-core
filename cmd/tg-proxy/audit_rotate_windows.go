//go:build windows

package main

import "golang.org/x/sys/windows"

// MoveFileEx with WRITE_THROUGH requests that the move reach disk before the
// call returns. rotateAuditLocked separately Syncs the new active file.
// Contract: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
func renameAuditFile(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_WRITE_THROUGH)
}

// Windows has no POSIX-style directory fsync. renameAuditFile supplies the
// write-through metadata barrier and rotateAuditLocked Syncs the replacement
// file, so no additional directory handle operation is required here.
func syncAuditDirectory(string) error {
	return nil
}
