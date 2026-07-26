//go:build integration && !windows

package main

import (
	"os/exec"
	"syscall"
)

// setNewProcessGroup configures cmd to start in a new process group so
// killProcessTree can terminate the whole tree (the proxy plus any
// children it spawns), not just the direct child, on test teardown.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree terminates the process group started by
// setNewProcessGroup.
func killProcessTree(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
