//go:build plan9 || js || wasip1

package main

import (
	"fmt"
	"os"
	"runtime"
)

func tryAuditFileLock(_ *os.File) (bool, error) {
	return false, fmt.Errorf("OS advisory file locking is unsupported on %s", runtime.GOOS)
}

func unlockAuditFile(_ *os.File) error {
	return fmt.Errorf("OS advisory file locking is unsupported on %s", runtime.GOOS)
}
