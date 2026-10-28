package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// hookChildEnv marks the supervised child so it evaluates instead of
// supervising again. It skips supervision only; every check still runs.
const hookChildEnv = "TG_HOOK_SUPERVISED_CHILD"

// hookSuperviseTimeout stays well below the client's default hook timeout,
// so the supervisor answers before the client gives up on the hook.
const hookSuperviseTimeout = 10 * time.Second

// maxHookChildStdout bounds the child's output; a decision is a few hundred bytes.
const maxHookChildStdout = 64 << 10

// hookDispatchRequested reports whether any argument names -dispatch. It is
// deliberately broad: supervising or failing closed when unsure is safe.
func hookDispatchRequested(args []string) bool {
	for _, a := range args {
		name := strings.TrimLeft(a, "-")
		if a != name && (name == "dispatch" || strings.HasPrefix(name, "dispatch=")) {
			return true
		}
	}
	return false
}

// superviseHook runs the hook evaluation in a child process started by
// newChild. Only a child that exits 0 within the timeout and writes exactly
// one well-formed PreToolUse object is trusted. Its allow, ask or deny is
// written again; an object without a decision writes nothing, so the
// client's own permission rules apply. Anything else denies.
func superviseHook(stdin io.Reader, stdout, stderr io.Writer, timeout time.Duration, newChild func(context.Context) *exec.Cmd) int {
	deny := func(why string) int {
		fmt.Fprintf(stderr, "tg hook: supervisor denied the call: %s\n", why)
		emitHookDecisionTo(stdout, "deny", "Tool Guard hook supervisor: "+why+"; failing closed (-dispatch)")
		return 0
	}
	const maxHookStdin = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
	if err != nil {
		return deny("stdin read error")
	}
	if len(raw) > maxHookStdin {
		return deny("oversized stdin")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	child := newChild(ctx)
	if child == nil {
		return deny("child process unavailable")
	}
	var out limitedBuffer
	out.max = maxHookChildStdout
	child.Stdin = bytes.NewReader(raw)
	child.Stdout = &out
	child.Stderr = stderr
	child.WaitDelay = time.Second
	runErr := child.Run()
	switch {
	case ctx.Err() != nil:
		return deny(fmt.Sprintf("evaluation timed out after %s", timeout))
	case runErr != nil:
		return deny(fmt.Sprintf("evaluation process failed: %v", runErr))
	case out.overflow:
		return deny("evaluation output too large")
	}

	dec := json.NewDecoder(bytes.NewReader(out.buf.Bytes()))
	dec.DisallowUnknownFields()
	var got hookOutput
	if err := dec.Decode(&got); err != nil {
		return deny("malformed evaluation output")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return deny("trailing evaluation output")
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" {
		return deny("unexpected hook event in evaluation output")
	}
	switch h.PermissionDecision {
	case "allow", "ask", "deny":
		emitHookDecisionTo(stdout, h.PermissionDecision, h.PermissionDecisionReason)
	case hookNoDecision:
		// No output: the client applies its own permission rules.
	default:
		return deny("unknown decision in evaluation output")
	}
	return 0
}

// hookChildCommand re-executes this binary with the same arguments as the
// supervised child.
func hookChildCommand(args []string) func(context.Context) *exec.Cmd {
	exe, err := os.Executable()
	return func(ctx context.Context) *exec.Cmd {
		if err != nil {
			return nil
		}
		c := exec.CommandContext(ctx, exe, append([]string{"hook"}, args...)...)
		c.Env = append(os.Environ(), hookChildEnv+"=1")
		return c
	}
}

// limitedBuffer keeps at most max bytes and records any overflow.
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		b.overflow = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}
