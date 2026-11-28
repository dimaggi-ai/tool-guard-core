//go:build !linux && !darwin

package main

import "os"

// review090hMaxRSS reports false: this system gives no peak resident size of
// a child process through os.ProcessState. The test then checks the live
// heap only.
func review090hMaxRSS(*os.ProcessState) (uint64, bool) {
	return 0, false
}
