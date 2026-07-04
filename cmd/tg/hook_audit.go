package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// appendHookAudit writes the hook's decision to a SHA-256 hash-chained JSONL
// log so the tg hook path leaves a tamper-evident record — the same audit
// property tg-proxy provides. Best-effort: an append failure does NOT change
// the decision (that was already made); the record is what's at risk, not the
// enforcement. Returns an error only for the caller to optionally log.
//
// The tail hash is read by seeking to the END of the file (not scanning the
// whole thing), so appending stays O(1) per call even as the log grows across
// a long agent session.
func appendHookAudit(path string, env *domain.ActionEnvelope, decision, reason string) error {
	dec, act := hookDecisionToDomain(decision)

	trace := domain.DecisionTrace{
		TraceID:        fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:      time.Now().UTC(),
		OrgID:          env.OrgID,
		EnvelopeID:     env.EnvelopeID,
		AgentID:        env.AgentID,
		SessionID:      env.SessionID,
		ToolName:       env.ToolName,
		ToolGroup:      env.ToolGroup,
		Decision:       dec,
		ActionTaken:    act,
		DecisionReason: reason,
	}

	// Serialize concurrent hook processes: two appends that both read the same
	// tail hash would fork the chain. A portable advisory lock (with a
	// staleness steal so a crashed holder can't wedge future appends) covers
	// read-tail → hash → append → sync.
	unlock, err := acquireAuditLock(path)
	if err != nil {
		return err
	}
	defer unlock()

	prev, err := lastTraceHash(path)
	if err != nil {
		return err
	}
	trace.PreviousTraceHash = prev
	h, err := audit.ComputeCanonicalTraceHash(&trace)
	if err != nil {
		return err
	}
	trace.TraceHash = h

	line, err := json.Marshal(&trace)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// acquireAuditLock takes a portable advisory lock on <path>.lock so concurrent
// hook processes serialize their read-tail-then-append and cannot fork the
// chain. Bounded (~200ms) with a staleness steal — a crashed holder does not
// wedge future appends. Returns an error (not a no-op unlock) on give-up so the
// caller skips this record rather than appending unlocked.
func acquireAuditLock(path string) (func(), error) {
	lock := path + ".lock"
	for i := 0; i < 100; i++ {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return func() { _ = f.Close(); _ = os.Remove(lock) }, nil
		}
		if fi, statErr := os.Stat(lock); statErr == nil && time.Since(fi.ModTime()) > 10*time.Second {
			_ = os.Remove(lock) // steal a stale lock (holder likely crashed)
			continue
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil, fmt.Errorf("audit: could not acquire lock %s", lock)
}

func hookDecisionToDomain(decision string) (domain.Decision, domain.ActionTaken) {
	switch decision {
	case "deny":
		return domain.DecisionDenied, domain.ActionDenied
	case "ask":
		return domain.DecisionEscalated, domain.ActionEscalated
	default:
		return domain.DecisionAllowed, domain.ActionAllowed
	}
}

// lastTraceHash returns the trace_hash of the last record in the chain, or
// "" if the file is empty/absent. It reads only the tail of the file.
func lastTraceHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() == 0 {
		return "", nil
	}

	const tail = 64 * 1024
	start := fi.Size() - tail
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	// If we started mid-file, the first line is a partial record — drop
	// everything up to and including the first newline. If the whole window
	// is one giant partial line (a record larger than the tail), we can't
	// recover a clean tail; fail rather than hash a partial.
	if start > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			return "", fmt.Errorf("audit tail: last record exceeds %d bytes", tail)
		}
	}

	// Take the last non-empty complete line (the file always ends in '\n' after
	// a successful append, so the final complete record is the last token).
	var lastLine []byte
	for _, ln := range bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'}) {
		if b := bytes.TrimSpace(ln); len(b) > 0 {
			lastLine = b
		}
	}
	if len(lastLine) == 0 {
		return "", nil
	}
	var rec struct {
		TraceHash string `json:"trace_hash"`
	}
	if err := json.Unmarshal(lastLine, &rec); err != nil {
		return "", fmt.Errorf("parse audit tail: %w", err)
	}
	return rec.TraceHash, nil
}
