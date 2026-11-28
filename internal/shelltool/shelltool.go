// Package shelltool holds the shell tool names that pkg/engine and cmd/tg
// share. It is internal, so the list is not part of the public Go API.
package shelltool

// Is reports whether the tool name is a known shell tool, i.e. one
// that executes a shell command string.
// `powershell` and `pwsh` are here because a PowerShell tool call still
// carries shell redirection: without them, `echo x > <protected path>` sent
// as a PowerShell tool call was allowed while the same string as a Bash tool
// call was denied. Measured 2026-11-09. This does NOT mean PowerShell
// cmdlets are understood — Set-Content, Out-File and Remove-Item are still
// not parsed as writes, and such commands escalate rather than deny.
// `run_shell_command` is the Gemini CLI shell tool name.
// engine.ViolatesProtectedPaths also runs the shell check for a tool whose group is
// "shell", which is the group `tg hook` gives a tool name it does not know.
func Is(tool string) bool {
	switch tool {
	case "bash", "shell", "sh", "run_command", "run_shell_command", "run", "exec", "command", "terminal":
		return true
	case "exec_command", "shell_command", "local_shell", "unified_exec", "container.exec":
		return true
	case "powershell", "pwsh":
		return true
	}
	return false
}
