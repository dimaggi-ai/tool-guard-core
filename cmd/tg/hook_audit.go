package main

import (
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
// Before resuming, the complete existing chain is verified under the append
// lock. This is O(n) in the log size, but prevents the hook from extending a
// chain that its own offline verifier already considers invalid.
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
		// Preserve the complete engine result. Reducing it to the hook's allow|ask|deny
		// response discards shadow-mode telemetry: a raw deny with
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
	// tail hash would fork the chain. A bounded OS advisory lock, released by
	// the kernel if its holder exits, covers verify → hash → append → sync.
	unlock, err := acquireAuditLock(path)
	if err != nil {
		return err
	}
	defer unlock()

	prev, needsSeparator, err := verifyHookAuditChain(path)
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

// appendHookAuditBestEffort preserves the hook decision when audit persistence fails
// but reports the lost record so operators do not mistake a silent gap for a complete
// audit trail.
func appendHookAuditBestEffort(stderr io.Writer, path string, env *domain.ActionEnvelope, result *domain.EvaluationResult, decision, reason string) {
	if err := appendHookAudit(path, env, result, decision, reason); err != nil {
		fmt.Fprintf(stderr, "tg hook: audit append failed — decision unchanged, record not written: %v\n", err)
	}
}

// acquireAuditLock takes an OS advisory lock on <path>.lock so concurrent hook
// processes serialize their verify-then-append transaction and cannot fork the
// chain. The kernel releases the lock when a holder exits, so crash recovery
// never relies on an unsafe age-based lockfile steal. The lockfile itself is
// intentionally persistent: removing it would let another process lock a new
// inode while the old inode is still locked.
//
// Acquisition remains bounded so audit contention cannot indefinitely delay a
// hook decision. Returns an error (not a no-op unlock) on give-up so the caller
// skips this record rather than appending unlocked.
func acquireAuditLock(path string) (func(), error) {
	const (
		wait  = 200 * time.Millisecond
		retry = 2 * time.Millisecond
	)
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open lock %s: %w", lockPath, err)
	}

	deadline := time.Now().Add(wait)
	for {
		locked, lockErr := tryAuditFileLock(f)
		if lockErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: lock %s: %w", lockPath, lockErr)
		}
		if locked {
			return func() {
				_ = unlockAuditFile(f)
				_ = f.Close()
			}, nil
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("audit: could not acquire lock %s within %s", lockPath, wait)
		}
		time.Sleep(retry)
	}
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

// verifyHookAuditChain replays the complete existing log before any append and
// returns its verified tail plus the physical JSONL delimiter state. A missing
// file is a new chain. The caller holds the hook append lock throughout.
func verifyHookAuditChain(path string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	defer f.Close()

	report, err := audit.VerifyChainFromReader(f)
	if err != nil {
		return "", false, fmt.Errorf("verify existing audit chain: %w", err)
	}
	if !report.Intact {
		return "", false, fmt.Errorf("existing audit chain failed at line %d: %s", report.FirstFailureAt, report.FailureReason)
	}
	needsSeparator, err := audit.NeedsRecordSeparator(f)
	if err != nil {
		return "", false, fmt.Errorf("inspect existing audit delimiter: %w", err)
	}
	return report.Tail, needsSeparator, nil
}
