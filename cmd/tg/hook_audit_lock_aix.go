//go:build aix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func tryAuditFileLock(f *os.File) (bool, error) {
	lock := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: 0,
		Start:  0,
		Len:    1,
	}
	err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock)
	if err == nil {
		return true, nil
	}
	if err == unix.EACCES || err == unix.EAGAIN {
		return false, nil
	}
	return false, err
}

func unlockAuditFile(f *os.File) error {
	lock := unix.Flock_t{
		Type:   unix.F_UNLCK,
		Whence: 0,
		Start:  0,
		Len:    1,
	}
	return unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock)
}
