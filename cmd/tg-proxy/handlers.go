package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// ── HTTP handlers ──────────────────────────────────────────────────────────
// Everything an operator hits via curl lives here. The proxy struct
// itself is defined in main.go; this file holds only request handlers
// and the access-log middleware.

func (p *proxy) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"started_at": p.startedAt.Format(time.RFC3339),
		"uptime_s":   int64(time.Since(p.startedAt).Seconds()),
	})
}

func (p *proxy) readyz(w http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	n := len(p.policies)
	p.mu.RUnlock()
	if n == 0 && p.failClosed {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":   "not_ready",
			"reason":   "no policies loaded and -fail-closed is set",
			"policies": 0,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "policies": n})
}

func (p *proxy) listPolicies(w http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]map[string]any, 0, len(p.policies))
	for _, pol := range p.policies {
		out = append(out, map[string]any{
			"policy_id":  pol.PolicyID,
			"name":       pol.Name,
			"version":    pol.Version,
			"mode":       pol.Mode,
			"status":     pol.Status,
			"rule_count": len(pol.Rules),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *proxy) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "tg_proxy_uptime_seconds %d\n", int64(time.Since(p.startedAt).Seconds()))
	fmt.Fprintf(w, "tg_proxy_policies_loaded %d\n", p.policyCount())
	fmt.Fprintf(w, "tg_proxy_policy_reloads_total %d\n", p.loadCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_total %d\n", p.evalCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_allowed_total %d\n", p.allowCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_denied_total %d\n", p.denyCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_escalated_total %d\n", p.escalateCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_flagged_total %d\n", p.flagCount.Load())
	fmt.Fprintf(w, "tg_proxy_evaluations_fail_closed_total %d\n", p.failClosedCount.Load())
	fmt.Fprintf(w, "tg_proxy_audit_append_failures_total %d\n", p.auditFailureCount.Load())
	// Read audit counters under the audit mutex; appendTrace mutates
	// them in another goroutine and -race would otherwise flag this.
	p.auditMu.Lock()
	auditBytes := p.auditCurrentBytes
	auditAppends := p.auditAppendSeq
	p.auditMu.Unlock()
	fmt.Fprintf(w, "tg_proxy_audit_current_bytes %d\n", auditBytes)
	fmt.Fprintf(w, "tg_proxy_audit_appends_total %d\n", auditAppends)
	fmt.Fprintf(w, "tg_proxy_regex_cache_size %d\n", engine.CachedRegexCount())
	fmt.Fprintf(w, "tg_proxy_rate_limit_keys %d\n", p.rateLimit.stats())
}

func (p *proxy) reloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, errBody("POST only"))
		return
	}
	if err := p.reload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loaded": p.policyCount()})
}

// evaluate is the headline endpoint. Body MUST be a valid
// ActionEnvelope JSON. The server runs the engine against the current
// policy set, appends the resulting DecisionTrace to the hash-chained
// audit log, and returns the EvaluationResult.
//
// Optional query parameters:
//
//	?mode=shadow|enforcement   — override the server's default mode for
//	                              this request only (subject to the
//	                              engine's strictest-mode floor).
func (p *proxy) evaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, errBody("POST only"))
		return
	}
	defer p.evalCount.Add(1)

	// Cap body at 1 MiB. We use http.MaxBytesReader rather than
	// io.LimitReader because the latter SILENTLY TRUNCATES at the
	// cap — a 1.2 MiB envelope would parse the first 1 MiB and
	// silently drop the rest, potentially trimming security-
	// relevant context fields. MaxBytesReader returns an error on
	// overflow so we reject the request cleanly.
	const maxBodyBytes = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		if dErr := validateJSONDepth(body, p.maxJSONDepth); dErr != nil {
			writeJSON(w, http.StatusBadRequest, errBody("envelope rejected: "+dErr.Error()))
			return
		}
	}
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody("read body: "+err.Error()))
		return
	}
	var env domain.ActionEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("decode envelope: "+err.Error()))
		return
	}
	if env.EnvelopeID == "" {
		env.EnvelopeID = fmt.Sprintf("env-%d", time.Now().UnixNano())
	}
	if env.Timestamp.IsZero() {
		env.Timestamp = time.Now().UTC()
	}

	// Rate limit (per agent/session/org per -rate-limit-key-by). Over
	// the bucket cap returns 429 with an audit-loggable reason; the
	// caller never reaches the engine.
	if p.rateLimit != nil {
		var key string
		switch p.rateLimitKeyBy {
		case "session_id":
			key = env.SessionID
		case "org_id":
			key = env.OrgID
		default:
			key = env.AgentID
		}
		if !p.rateLimit.allow(key) {
			reason := fmt.Sprintf("rate limit exceeded for %s=%q", p.rateLimitKeyBy, key)
			p.emitBoundaryDeny(&env, reason, p.defaultMode)
			p.denyCount.Add(1)
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"decision":        "denied",
				"action_taken":    "denied",
				"decision_reason": reason,
				"effective_mode":  p.defaultMode,
			})
			return
		}
	}

	mode := p.defaultMode
	switch r.URL.Query().Get("mode") {
	case "shadow":
		mode = domain.PolicyModeShadow
	case "enforcement":
		mode = domain.PolicyModeEnforcement
	}

	p.mu.RLock()
	policies := p.policies
	p.mu.RUnlock()

	if len(policies) == 0 && p.failClosed {
		reason := "no policies loaded; fail-closed engaged"
		p.emitBoundaryDeny(&env, reason, mode)
		p.failClosedCount.Add(1)
		p.denyCount.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"decision":        "denied",
			"action_taken":    "denied",
			"decision_reason": reason,
			"effective_mode":  mode,
		})
		return
	}

	result := p.eval.Evaluate(&env, policies, mode)

	// Tool-name spoof guard. When -unknown-tools-deny is set, any
	// envelope whose tool_name is not declared in scope.tool_names of
	// some loaded ENFORCEMENT policy is denied — even if a policy
	// happened to match via tool_groups. This closes the family of
	// variant names (DROP_TABLE, drop_tables, drop_table_v2).
	if p.unknownToolsDeny && !toolNameKnown(env.ToolName, policies) {
		// Counter increment happens once in the final switch, not
		// here — earlier code double-counted unknown-tool denies.
		result.Decision = domain.DecisionDenied
		result.ActionTaken = domain.ActionDenied
		result.DecisionReason = fmt.Sprintf(
			"tool_name %q is not declared in scope.tool_names of any loaded policy (--unknown-tools-deny)",
			env.ToolName,
		)
	}

	traceID := fmt.Sprintf("trc-%d", time.Now().UnixNano())
	trace := domain.DecisionTrace{
		TraceID:              traceID,
		Timestamp:            env.Timestamp.UTC(),
		OrgID:                env.OrgID,
		EnvelopeID:           env.EnvelopeID,
		AgentID:              env.AgentID,
		AgentVersion:         env.AgentVersion,
		SessionID:            env.SessionID,
		TurnNumber:           env.TurnNumber,
		ToolName:             env.ToolName,
		ToolGroup:            env.ToolGroup,
		Amount:               amountFromEnvelope(&env),
		Decision:             result.Decision,
		ActionTaken:          result.ActionTaken,
		DecisionReason:       result.DecisionReason,
		Mode:                 result.EffectiveMode,
		PoliciesMatched:      result.PoliciesMatched,
		RulesEvaluated:       result.RulesEvaluated,
		RulesTriggered:       result.RulesTriggered,
		RuleResults:          result.RuleResults,
		PrimaryCitation:      result.PrimaryCitation,
		SuggestedResponse:    result.SuggestedResponse,
		IsNearMiss:           result.IsNearMiss,
		EvaluationDurationMs: 0,
	}
	// When the decision is escalated, register the pending entry so
	// the approver endpoints can find it and the agent can poll.
	// EnvelopeID serves as the escalation ID. The per-rule
	// EffectConfig.TimeoutMinutes (if set) overrides the default.
	//
	// add() returns nil on either (a) envelope_id collision with an
	// existing entry, or (b) the store is at the hard pending-cap.
	// Both are downgraded to deny here — escalating with a duplicate
	// poll URL would let an agent see another entry's approval
	// state, and escalating past the cap would silently drop the
	// pending entry. Better to surface a clean deny.
	if result.Decision == domain.DecisionEscalated {
		timeoutMin := p.escalationDefaultMin
		if t := timeoutFromMatchedRules(result, policies); t > 0 {
			timeoutMin = t
		}
		if registered := p.escalations.add(&env, result, timeoutMin); registered == nil {
			result.Decision = domain.DecisionDenied
			result.ActionTaken = domain.ActionDenied
			result.DecisionReason = "escalation could not be registered (envelope_id collision or pending-store at cap); downgraded to deny"
			trace.Decision = result.Decision
			trace.ActionTaken = result.ActionTaken
			trace.DecisionReason = result.DecisionReason
		}
	}

	// Append the audit trace, downgrading allow→deny if the chain
	// can't be written and --fail-closed is set. Counter updates
	// happen once at the very end against the FINAL decision so
	// there are no underflow / double-count races.
	auditErr := p.appendTrace(&trace)
	if auditErr != nil {
		log.Printf("tg-proxy: append audit trace: %v", auditErr)
		p.auditFailureCount.Add(1)
		if p.failClosed && result.Decision == domain.DecisionAllowed {
			result.Decision = domain.DecisionDenied
			result.ActionTaken = domain.ActionDenied
			result.DecisionReason = "decision was allow but audit append failed; downgraded to deny (--fail-closed=true)"
			trace.Decision = result.Decision
			trace.ActionTaken = result.ActionTaken
			trace.DecisionReason = result.DecisionReason
			_ = p.appendTrace(&trace) // best-effort log of the override
		}
	}

	switch result.Decision {
	case domain.DecisionAllowed:
		p.allowCount.Add(1)
	case domain.DecisionDenied:
		p.denyCount.Add(1)
	case domain.DecisionEscalated:
		p.escalateCount.Add(1)
	case domain.DecisionFlagged:
		p.flagCount.Add(1)
	}

	if result.Decision == domain.DecisionEscalated {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"decision":           result.Decision,
			"action_taken":       result.ActionTaken,
			"decision_reason":    result.DecisionReason,
			"effective_mode":     result.EffectiveMode,
			"policies_matched":   result.PoliciesMatched,
			"rules_evaluated":    result.RulesEvaluated,
			"rules_triggered":    result.RulesTriggered,
			"rule_results":       result.RuleResults,
			"primary_citation":   result.PrimaryCitation,
			"is_near_miss":       result.IsNearMiss,
			"suggested_response": result.SuggestedResponse,
			"envelope_id":        env.EnvelopeID,
			"escalation_id":      env.EnvelopeID,
			"poll_url":           "/escalations/" + env.EnvelopeID,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// withLogging is a minimal access log so operators see request volume
// and errors. Production deployments will likely front this with their
// own reverse proxy or Envoy.
func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(rw, r)
		log.Printf("%s %s → %d in %s", r.Method, r.URL.Path, rw.status, time.Since(t0))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
