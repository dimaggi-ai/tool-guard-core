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
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// appendHookAudit writes the hook's decision to a SHA-256 hash-chained JSONL
// log so the tg hook path leaves a tamper-evident record — the same audit
// property tg-proxy provides. Best-effort: an append failure does NOT change
// the decision (that was already made); the record is what's at risk, not the
// enforcement. Returns an error only for the caller to optionally log.
//
// The tail hash is read from a verifier-sized window at the END of the file
// (not by scanning the whole thing), so appending stays O(1) per call even as
// the log grows across a long agent session.
func appendHookAudit(path string, env *domain.ActionEnvelope, result *domain.EvaluationResult, decision, reason string) error {
	amount, amountStatus := engine.EvaluatedAmount(env)
	timestamp := env.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	trace := domain.DecisionTrace{
		CanonicalVersion:   audit.CanonicalTraceVersion,
		TraceID:            fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:          timestamp.UTC(),
		OrgID:              env.OrgID,
		EnvelopeID:         env.EnvelopeID,
		AgentID:            env.AgentID,
		AgentVersion:       env.AgentVersion,
		SessionID:          env.SessionID,
		TurnNumber:         env.TurnNumber,
		ToolName:           env.ToolName,
		ToolGroup:          env.ToolGroup,
		Amount:             amount,
		AmountParseStatus:  amountStatus,
		ParametersRedacted: append([]byte(nil), env.ParametersRedacted...),
	}
	if result == nil {
		// Pre-evaluation operational decisions have no engine provenance. Keep a
		// synthetic outcome for those paths only (protected paths, load errors,
		// unknown-tool rejection, and configured fail-open/fail-closed handling).
		trace.Decision, trace.ActionTaken = hookDecisionToDomain(decision)
		trace.DecisionReason = reason
	} else {
		// Preserve the engine's complete result. Reducing this to the hook's
		// allow|ask|deny response discards shadow-mode telemetry: a raw deny with
		// action_taken=allowed_shadow must remain visible in the audit record.
		trace.Decision = result.Decision
		trace.ActionTaken = result.ActionTaken
		trace.DecisionReason = result.DecisionReason
		trace.Mode = result.EffectiveMode
		trace.PoliciesMatched = result.PoliciesMatched
		trace.RulesEvaluated = result.RulesEvaluated
		trace.RulesTriggered = result.RulesTriggered
		trace.RuleResults = result.RuleResults
		trace.AppliedRuleResults = result.AppliedRuleResults
		trace.PrimaryCitation = result.PrimaryCitation
		trace.AppliedPrimaryCitation = result.AppliedPrimaryCitation
		trace.SuggestedResponse = result.SuggestedResponse
		trace.IsNearMiss = result.IsNearMiss
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

	line, err := audit.MarshalTraceRecord(&trace)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	needsSeparator, err := audit.NeedsRecordSeparator(f)
	if err != nil {
		return err
	}
	record := make([]byte, 0, len(line)+2)
	if needsSeparator {
		record = append(record, '\n')
	}
	record = append(record, line...)
	record = append(record, '\n')
	n, err := f.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	return f.Sync()
}

// appendHookAuditBestEffort preserves the hook decision when audit persistence
// fails, but reports the lost record so operators do not mistake a silent gap
// for a complete audit trail.
func appendHookAuditBestEffort(stderr io.Writer, path string, env *domain.ActionEnvelope, result *domain.EvaluationResult, decision, reason string) {
	if err := appendHookAudit(path, env, result, decision, reason); err != nil {
		fmt.Fprintf(stderr, "tg hook: audit append failed — decision unchanged, record not written: %v\n", err)
	}
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
// "" if the file is empty/absent. It reads at most one verifier-sized record
// from the tail; an oversized record fails instead of silently starting a new
// chain.
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
	if err := validateAuditGenesis(f, fi.Size()); err != nil {
		return "", err
	}

	// The streaming verifier permits empty LF and CRLF records. Seek backward
	// past that complete suffix before applying the bounded-record window so
	// any number of blank lines cannot consume delimiter headroom and make a
	// valid exact-max tail look oversized. A bare CR is record content under
	// bufio.ScanLines, so only skip one when it immediately precedes an LF.
	logicalEnd := fi.Size()
	chunk := make([]byte, 4096)
	afterLF := false

scanBlankSuffix:
	for logicalEnd > 0 {
		chunkStart := logicalEnd - int64(len(chunk))
		if chunkStart < 0 {
			chunkStart = 0
		}
		n, readErr := f.ReadAt(chunk[:logicalEnd-chunkStart], chunkStart)
		if readErr != nil && readErr != io.EOF {
			return "", readErr
		}
		i := n - 1
		for i >= 0 {
			switch {
			case chunk[i] == '\n':
				afterLF = true
				i--
			case chunk[i] == '\r' && afterLF:
				afterLF = false
				i--
			default:
				logicalEnd = chunkStart + int64(i+1)
				break scanBlankSuffix
			}
		}
		logicalEnd = chunkStart
	}
	if logicalEnd == 0 {
		return "", nil
	}

	// Include one preceding delimiter. That distinguishes a complete
	// max-sized final record from a window beginning inside an oversized one.
	tailWindow := int64(audit.MaxTraceRecordBytes + 1)
	start := logicalEnd - tailWindow
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	data := make([]byte, logicalEnd-start)
	if _, err := io.ReadFull(f, data); err != nil {
		return "", err
	}

	// Use the final remaining delimiter as the start boundary of the last
	// record. If the bounded window starts mid-file and contains no delimiter,
	// the final record is too large for the verifier as well.
	var lastLine []byte
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		lastLine = data[i+1:]
	} else {
		if start > 0 {
			return "", fmt.Errorf("audit tail: last record exceeds %d bytes", audit.MaxTraceRecordBytes)
		}
		lastLine = data
	}
	if len(lastLine) > audit.MaxTraceRecordBytes {
		return "", fmt.Errorf("audit tail: last record exceeds %d bytes", audit.MaxTraceRecordBytes)
	}
	if len(lastLine) == 0 {
		return "", nil
	}
	if len(bytes.TrimSpace(lastLine)) == 0 {
		return "", fmt.Errorf("audit tail: whitespace-only trailing record")
	}
	var rec domain.DecisionTrace
	if err := json.Unmarshal(lastLine, &rec); err != nil {
		return "", fmt.Errorf("parse audit tail: %w", err)
	}
	ok, err := audit.VerifyCanonicalTraceHash(&rec)
	if err != nil {
		return "", fmt.Errorf("verify audit tail: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("verify audit tail: trace %q hash mismatch", rec.TraceID)
	}
	return rec.TraceHash, nil
}

// validateAuditGenesis rejects a detached prefix before the bounded tail read.
// Reading stops after the first non-empty record, so normal appends do not
// replay the whole log; operators still use `tg verify` for complete-chain
// validation. io.NewSectionReader keeps this check independent of f's offset.
func validateAuditGenesis(f *os.File, size int64) error {
	sc := bufio.NewScanner(io.NewSectionReader(f, 0, size))
	sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTraceRecordScanBytes)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) > audit.MaxTraceRecordBytes {
			return fmt.Errorf("audit genesis: record exceeds %d bytes", audit.MaxTraceRecordBytes)
		}
		if len(raw) == 0 {
			continue
		}
		var genesis domain.DecisionTrace
		if err := json.Unmarshal(raw, &genesis); err != nil {
			return fmt.Errorf("audit genesis line %d: parse JSON: %w", line, err)
		}
		if genesis.PreviousTraceHash != "" {
			return fmt.Errorf("audit genesis line %d: previous_trace_hash must be empty, got %q", line, genesis.PreviousTraceHash)
		}
		ok, err := audit.VerifyCanonicalTraceHash(&genesis)
		if err != nil {
			return fmt.Errorf("audit genesis line %d: canonical hash: %w", line, err)
		}
		if !ok {
			return fmt.Errorf("audit genesis line %d: trace %q hash mismatch", line, genesis.TraceID)
		}
		return nil
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("audit genesis: scan: %w", err)
	}
	return nil
}
