//go:build darwin

package main

import (
	"os"
	"syscall"
)

// review090hMaxRSS returns the peak resident size of a finished process in
// bytes. On macOS the kernel reports it in bytes.
func review090hMaxRSS(ps *os.ProcessState) (uint64, bool) {
	if ps == nil {
		return 0, false
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0, false
	}
	return uint64(ru.Maxrss), true
}
