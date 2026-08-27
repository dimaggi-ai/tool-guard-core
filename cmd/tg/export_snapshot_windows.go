//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func createAuditSnapshotFile() (*os.File, string, error) {
	dir, err := os.MkdirTemp("", "toolguard-audit-export-*")
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "snapshot")
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(dir)
		return nil, "", err
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE,
		0,
	)
	if err != nil {
		_ = os.Remove(dir)
		return nil, "", err
	}
	return os.NewFile(uintptr(handle), path), dir, nil
}
