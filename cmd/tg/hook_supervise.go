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

// hookChildArg is the first argument the supervisor passes to its child so
// the child evaluates instead of supervising again. It is an argument, not an
// environment variable, so only the configured hook command can set it. It
// skips supervision only; every check still runs.
const hookChildArg = "-tg-supervised-child"

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
	// The deadline covers reading stdin too: a pipe that stays open must not
	// hold the hook past it.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	const maxHookStdin = 1 << 20
	type readResult struct {
		raw []byte
		err error
	}
	read := make(chan readResult, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
		read <- readResult{raw, err}
	}()
	var raw []byte
	select {
	case <-ctx.Done():
		return deny(fmt.Sprintf("stdin not closed within %s", timeout))
	case r := <-read:
		if r.err != nil {
			return deny("stdin read error")
		}
		raw = r.raw
	}
	if len(raw) > maxHookStdin {
		return deny("oversized stdin")
	}

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

	fields, err := parseChildHookOutput(out.buf.Bytes())
	if err != nil {
		return deny("malformed evaluation output: " + err.Error())
	}
	if fields["hookEventName"] != "PreToolUse" {
		return deny("unexpected hook event in evaluation output")
	}
	decision, present := fields["permissionDecision"]
	switch {
	case !present:
		// No output: the client applies its own permission rules.
	case decision == "allow" || decision == "ask" || decision == "deny":
		emitHookDecisionTo(stdout, decision, fields["permissionDecisionReason"])
	default:
		return deny("unknown decision in evaluation output")
	}
	return 0
}

// parseChildHookOutput accepts exactly one object of the form
// {"hookSpecificOutput":{...}} whose inner keys are hookEventName,
// permissionDecision and permissionDecisionReason, each at most once and each
// a JSON string. Null, other types, duplicate or unknown keys and trailing
// data are errors.
func parseChildHookOutput(b []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	expectDelim := func(want json.Delim) error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); !ok || d != want {
			return fmt.Errorf("expected %q", want)
		}
		return nil
	}
	if err := expectDelim('{'); err != nil {
		return nil, err
	}
	if t, err := dec.Token(); err != nil || t != "hookSpecificOutput" {
		return nil, errors.New("expected hookSpecificOutput")
	}
	if err := expectDelim('{'); err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		switch key {
		case "hookEventName", "permissionDecision", "permissionDecisionReason":
		default:
			return nil, fmt.Errorf("unexpected key %q", key)
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		v, err := dec.Token()
		if err != nil {
			return nil, err
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("key %q is not a string", key)
		}
		fields[key] = s
	}
	if err := expectDelim('}'); err != nil {
		return nil, err
	}
	if err := expectDelim('}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return fields, nil
}

// hookChildCommand re-executes this binary with the same arguments as the
// supervised child.
func hookChildCommand(args []string) func(context.Context) *exec.Cmd {
	exe, err := os.Executable()
	return func(ctx context.Context) *exec.Cmd {
		if err != nil {
			return nil
		}
		return exec.CommandContext(ctx, exe, append([]string{"hook", hookChildArg}, args...)...)
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
