package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// ── helpers ────────────────────────────────────────────────────────────────
// Small utilities shared across handlers / audit / policy loading.

func evaluatedAmountFromEnvelope(env *domain.ActionEnvelope) (float64, string) {
	return engine.EvaluatedAmount(env)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func errBody(msg string) map[string]any { return map[string]any{"error": msg} }

// validateJSONDepth runs a streaming token walk to confirm the JSON
// in body never nests deeper than maxDepth. Defeats the recursive-JSON
// DoS class — real envelopes are flat objects with a single nested
// parameters map; the proxy default of 32 is well above legitimate use
// but far below what would let an attacker stack-overflow the decoder.
// The caller chooses maxDepth via the -max-envelope-depth flag.
func validateJSONDepth(body []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return fmt.Errorf("JSON nesting depth %d exceeds maximum %d", depth, maxDepth)
				}
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// timeoutFromMatchedRules selects timeout configuration only from matched
// enforcement-mode escalation rules. RuleResults are already ordered by
// policy priority, so the first qualifying non-zero value wins
// deterministically. Shadow rules are telemetry and must not mutate pending
// enforcement state. Returns 0 if none set so callers use the proxy default.
func timeoutFromMatchedRules(result *domain.EvaluationResult, policies []domain.Policy) int {
	for _, rr := range result.RuleResults {
		if !rr.Matched || rr.Effect != domain.EffectEscalate {
			continue
		}
		for _, p := range policies {
			if p.PolicyID != rr.PolicyID || p.Version != rr.PolicyVersion || p.Mode == domain.PolicyModeShadow {
				continue
			}
			for _, rule := range p.Rules {
				if rule.RuleID == rr.RuleID && rule.Effect == domain.EffectEscalate && rule.EffectConfig.TimeoutMinutes > 0 {
					return rule.EffectConfig.TimeoutMinutes
				}
			}
		}
	}
	return 0
}

// emitBoundaryDeny writes an audit trace for a deny that happens
// BEFORE the engine evaluates (rate-limit overflow, fail-closed
// no-policies). These decisions are real enforcement events and must
// enter the hash chain so a verifier can replay them — otherwise the
// chain has a gap between the last engine-evaluated trace and the
// next one, and "what got denied" is unrecoverable.
//
// The trace carries the boundary reason as DecisionReason; no rule
// results since no rule fired. Errors are logged but never propagate
// to the caller — the deny response must still go out even if audit
// append failed; that's a separate failure surfaced via metrics.
func (p *proxy) emitBoundaryDeny(env *domain.ActionEnvelope, reason string, mode domain.PolicyMode) {
	amount, amountStatus := evaluatedAmountFromEnvelope(env)
	trace := domain.DecisionTrace{
		TraceID:           fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:         time.Now().UTC(),
		OrgID:             env.OrgID,
		EnvelopeID:        env.EnvelopeID,
		AgentID:           env.AgentID,
		AgentVersion:      env.AgentVersion,
		SessionID:         env.SessionID,
		TurnNumber:        env.TurnNumber,
		ToolName:          env.ToolName,
		ToolGroup:         env.ToolGroup,
		Amount:            amount,
		AmountParseStatus: amountStatus,
		Decision:          domain.DecisionDenied,
		ActionTaken:       domain.ActionDenied,
		DecisionReason:    reason,
		Mode:              mode,
	}
	if err := p.appendTrace(&trace); err != nil {
		log.Printf("tg-proxy: emitBoundaryDeny audit: %v", err)
		p.auditFailureCount.Add(1)
	}
}

// emitEscalationResolution writes an audit trace for the human
// decision on a previously-escalated request. The DecisionTrace carries
// the new state (allowed if approved, denied if denied) so the chain
// records the FINAL outcome alongside the original escalate event.
//
// AgentID/SessionID/OrgID/Tool* are copied from the original envelope
// so the trace is queryable on the same identity axes as the rest of
// the chain.
func (p *proxy) emitEscalationResolution(e *Escalation, approved bool) error {
	var (
		decision    domain.Decision
		actionTaken domain.ActionTaken
		reason      string
	)
	if approved {
		decision = domain.DecisionAllowed
		actionTaken = domain.ActionAllowed
		reason = fmt.Sprintf("escalation %s approved by %q: %s", e.ID, e.Approver, e.ApproverReason)
	} else {
		decision = domain.DecisionDenied
		actionTaken = domain.ActionDenied
		reason = fmt.Sprintf("escalation %s denied by %q: %s", e.ID, e.Approver, e.ApproverReason)
	}
	amount, amountStatus := evaluatedAmountFromEnvelope(&e.Envelope)
	trace := domain.DecisionTrace{
		TraceID:           fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:         time.Now().UTC(),
		OrgID:             e.Envelope.OrgID,
		EnvelopeID:        e.Envelope.EnvelopeID,
		AgentID:           e.Envelope.AgentID,
		AgentVersion:      e.Envelope.AgentVersion,
		SessionID:         e.Envelope.SessionID,
		TurnNumber:        e.Envelope.TurnNumber,
		ToolName:          e.Envelope.ToolName,
		ToolGroup:         e.Envelope.ToolGroup,
		Amount:            amount,
		AmountParseStatus: amountStatus,
		Decision:          decision,
		ActionTaken:       actionTaken,
		DecisionReason:    reason,
	}
	if err := p.appendTrace(&trace); err != nil {
		log.Printf("tg-proxy: emitEscalationResolution audit: %v", err)
		p.auditFailureCount.Add(1)
		if errors.Is(err, errAuditRecordCommitted) {
			// The full record is part of the live chain; only its explicit
			// durability barrier failed. Commit the matching in-memory state so
			// the log and approval registry cannot contradict each other.
			return nil
		}
		return err
	}
	return nil
}

// splitCommaPaths parses a comma-separated path list into a slice, trimming
// blanks. Values are left as-is; engine.ViolatesProtectedPaths cleans them.
func splitCommaPaths(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// short truncates a hash for log output.
func short(h string) string {
	if h == "" {
		return "(empty)"
	}
	if len(h) <= 19 {
		return h
	}
	return h[:19] + "…"
}
