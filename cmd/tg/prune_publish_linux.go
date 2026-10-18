//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishPrunedFile(temp, out string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, temp, unix.AT_FDCWD, out, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish without replacement: %w", err)
	}
	dir, err := os.Open(filepath.Dir(out))
	if err == nil {
		defer dir.Close()
		err = dir.Sync()
	}
	if err != nil {
		return fmt.Errorf("output published but directory durability is uncertain: %w", err)
	}
	return nil
}
