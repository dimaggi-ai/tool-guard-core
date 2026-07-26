//go:build integration && windows

package main

import "os/exec"

// setNewProcessGroup is a no-op on Windows: POSIX process groups don't
// exist there, and this test harness's spawned tg-proxy doesn't fork
// further children, so the plain kill in killProcessTree below is
// sufficient without one.
func setNewProcessGroup(cmd *exec.Cmd) {}

// killProcessTree terminates the process directly. There is no simple
// Windows equivalent of "kill the whole POSIX process group" without
// CREATE_NEW_PROCESS_GROUP + GenerateConsoleCtrlEvent machinery this test
// harness doesn't need - the spawned tg-proxy is the only process to
// clean up.
func killProcessTree(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
}
