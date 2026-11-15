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
func superviseHook(stdin io.Reader, stdout, stderr io.Writer, timeout time.Duration, newChild func(context.Context) *exec.Cmd, args ...string) int {
	dialect := argsHookDialect(args)
	deny := func(why string) int {
		fmt.Fprintf(stderr, "tg hook: supervisor denied the call: %s\n", why)
		emitHookDecisionDialect(stdout, dialect, "force_ask", "deny", "Tool Guard hook supervisor: "+why+"; failing closed (-dispatch)")
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
	var in hookInput
	if json.Unmarshal(raw, &in) == nil && dialect == dialectBoth {
		dialect = resolveHookDialect("auto", in.ToolCall != nil)
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
	_, hasClaude := fields["hookEventName"]
	_, hasAgy := fields["decision"]
	if (dialect == dialectClaude && !hasClaude) || (dialect == dialectAntigravity && !hasAgy) ||
		(dialect == dialectBoth && (!hasClaude || !hasAgy)) {
		return deny("evaluation output does not cover the input dialect")
	}
	if hasClaude && !hasAgy && fields["permissionDecision"] == hookNoDecision {
		return 0 // The client applies its own permission rules.
	}
	_, _ = stdout.Write(out.buf.Bytes())
	return 0
}

// parseChildHookOutput accepts exactly one object using either or both hook
// contracts. All leaf values must be strings. Unknown or duplicate keys,
// trailing data, invalid decisions and conflicting dialect decisions fail.
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
	fields := map[string]string{}
	seen := map[string]bool{}
	readString := func(key string) error {
		v, err := dec.Token()
		if err != nil {
			return err
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("key %q is not a string", key)
		}
		fields[key] = s
		return nil
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		if seen[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		switch key {
		case "hookSpecificOutput":
			if err := expectDelim('{'); err != nil {
				return nil, err
			}
			for dec.More() {
				t, err := dec.Token()
				if err != nil {
					return nil, err
				}
				inner, _ := t.(string)
				if inner != "hookEventName" && inner != "permissionDecision" && inner != "permissionDecisionReason" {
					return nil, fmt.Errorf("unexpected key %q", inner)
				}
				if _, duplicate := fields[inner]; duplicate {
					return nil, fmt.Errorf("duplicate key %q", inner)
				}
				if err := readString(inner); err != nil {
					return nil, err
				}
			}
			if err := expectDelim('}'); err != nil {
				return nil, err
			}
		case "decision", "reason":
			if err := readString(key); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected key %q", key)
		}
	}
	if err := expectDelim('}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	if !seen["hookSpecificOutput"] && !seen["decision"] {
		return nil, errors.New("missing decision contract")
	}
	if seen["hookSpecificOutput"] {
		if fields["hookEventName"] != "PreToolUse" {
			return nil, errors.New("unexpected hook event")
		}
		if d, present := fields["permissionDecision"]; present && d != "allow" && d != "ask" && d != "deny" {
			return nil, errors.New("unknown permission decision")
		}
	}
	if seen["reason"] && !seen["decision"] {
		return nil, errors.New("reason without decision")
	}
	if seen["decision"] {
		d := fields["decision"]
		if d != "allow" && d != "ask" && d != "force_ask" && d != "deny" {
			return nil, errors.New("unknown top-level decision")
		}
		if d == "force_ask" {
			d = "ask"
		}
		if seen["hookSpecificOutput"] && fields["permissionDecision"] != d {
			return nil, errors.New("conflicting dialect decisions")
		}
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
