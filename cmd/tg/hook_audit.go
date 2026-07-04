package main

import (
	"bufio"
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

	// Take the last non-empty line. If we started mid-file, the first
	// (partial) line is discarded by only ever using the LAST complete one.
	var lastLine []byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 128*1024), 4*1024*1024)
	for sc.Scan() {
		if b := bytes.TrimSpace(sc.Bytes()); len(b) > 0 {
			lastLine = append(lastLine[:0], b...)
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
