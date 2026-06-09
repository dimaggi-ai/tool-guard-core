package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ── helpers ────────────────────────────────────────────────────────────────
// Small utilities shared across handlers / audit / policy loading.

func amountFromEnvelope(env *domain.ActionEnvelope) float64 {
	a, _ := env.Amount()
	return a
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

// toolNameKnown reports whether toolName is explicitly declared in
// scope.tool_names of any loaded ENFORCEMENT policy. Used by the
// --unknown-tools-deny flag to refuse evaluation of name variants the
// operator never authorised. Shadow-mode policies are excluded — a
// shadow rollout that lists a tool "for observation" must NOT make the
// unknown-tools gate pass.
func toolNameKnown(toolName string, policies []domain.Policy) bool {
	if toolName == "" {
		return false
	}
	for _, p := range policies {
		if p.Mode != domain.PolicyModeEnforcement {
			continue
		}
		for _, n := range p.Scope.ToolNames {
			if n == toolName {
				return true
			}
		}
	}
	return false
}

// timeoutFromMatchedRules walks the rules that fired (and the policies
// they came from) looking for an EffectConfig.TimeoutMinutes. First
// non-zero value wins. Returns 0 if none set so callers can fall back
// to the proxy's default.
func timeoutFromMatchedRules(result *domain.EvaluationResult, policies []domain.Policy) int {
	for _, rr := range result.RuleResults {
		if !rr.Matched {
			continue
		}
		for _, p := range policies {
			if p.PolicyID != rr.PolicyID {
				continue
			}
			for _, rule := range p.Rules {
				if rule.RuleID == rr.RuleID && rule.EffectConfig.TimeoutMinutes > 0 {
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
	trace := domain.DecisionTrace{
		TraceID:        fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:      time.Now().UTC(),
		OrgID:          env.OrgID,
		EnvelopeID:     env.EnvelopeID,
		AgentID:        env.AgentID,
		AgentVersion:   env.AgentVersion,
		SessionID:      env.SessionID,
		TurnNumber:     env.TurnNumber,
		ToolName:       env.ToolName,
		ToolGroup:      env.ToolGroup,
		Amount:         amountFromEnvelope(env),
		Decision:       domain.DecisionDenied,
		ActionTaken:    domain.ActionDenied,
		DecisionReason: reason,
		Mode:           mode,
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
func (p *proxy) emitEscalationResolution(e *Escalation, approved bool) {
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
	trace := domain.DecisionTrace{
		TraceID:        fmt.Sprintf("trc-%d", time.Now().UnixNano()),
		Timestamp:      time.Now().UTC(),
		OrgID:          e.Envelope.OrgID,
		EnvelopeID:     e.Envelope.EnvelopeID,
		AgentID:        e.Envelope.AgentID,
		AgentVersion:   e.Envelope.AgentVersion,
		SessionID:      e.Envelope.SessionID,
		TurnNumber:     e.Envelope.TurnNumber,
		ToolName:       e.Envelope.ToolName,
		ToolGroup:      e.Envelope.ToolGroup,
		Amount:         amountFromEnvelope(&e.Envelope),
		Decision:       decision,
		ActionTaken:    actionTaken,
		DecisionReason: reason,
	}
	if err := p.appendTrace(&trace); err != nil {
		log.Printf("tg-proxy: emitEscalationResolution audit: %v", err)
		p.auditFailureCount.Add(1)
	}
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
