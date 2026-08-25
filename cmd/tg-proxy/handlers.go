package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// evaluationResponse augments only the proxy wire response. The pure engine's
// domain.EvaluationResult deliberately remains receipt-agnostic.
type evaluationResponse struct {
	*domain.EvaluationResult
	DecisionReceipt *audit.DecisionReceipt `json:"decision_receipt,omitempty"`
}

func addDecisionReceipt(body map[string]any, receipt *audit.DecisionReceipt) map[string]any {
	if receipt != nil {
		body["decision_receipt"] = receipt
	}
	return body
}

// ── HTTP handlers ──────────────────────────────────────────────────────────
// Everything an operator hits via curl lives here. The proxy struct
// itself is defined in main.go; this file holds only request handlers
// and the access-log middleware.

func (p *proxy) healthz(w http.ResponseWriter, r *http.Request) {
	if !requireHTTPMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"started_at": p.startedAt.Format(time.RFC3339),
		"uptime_s":   int64(time.Since(p.startedAt).Seconds()),
	})
}

func (p *proxy) readyz(w http.ResponseWriter, r *http.Request) {
	if !requireHTTPMethod(w, r, http.MethodGet) {
		return
	}
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

func (p *proxy) listPolicies(w http.ResponseWriter, r *http.Request) {
	if !requireHTTPMethod(w, r, http.MethodGet) {
		return
	}
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

func (p *proxy) metrics(w http.ResponseWriter, r *http.Request) {
	if !requireHTTPMethod(w, r, http.MethodGet) {
		return
	}
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
	fmt.Fprintf(w, "tg_proxy_velocity_keys %d\n", p.velocity.stats())
}

func requireHTTPMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, errBody(method+" only"))
	return false
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

	// Capture policies and their digest atomically. The same snapshot must
	// drive both evaluation and audit provenance even if SIGHUP reloads the
	// server before the trace is appended.
	p.mu.RLock()
	policies := p.policies
	policySetHash := p.policySetHash
	p.mu.RUnlock()

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
			receipt := p.emitBoundaryDeny(&env, reason, p.defaultMode, policySetHash)
			p.denyCount.Add(1)
			writeJSON(w, http.StatusTooManyRequests, addDecisionReceipt(map[string]any{
				"decision":        "denied",
				"action_taken":    "denied",
				"decision_reason": reason,
				"effective_mode":  p.defaultMode,
			}, receipt))
			return
		}
	}

	mode := p.defaultMode
	switch q := r.URL.Query().Get("mode"); q {
	case "shadow":
		mode = domain.PolicyModeShadow
	case "enforcement":
		mode = domain.PolicyModeEnforcement
	case "":
	default:
		writeJSON(w, http.StatusBadRequest, errBody("unknown mode (must be shadow|enforcement)"))
		return
	}

	// Protected-path guard (-protect-paths / -protect-self). Runs BEFORE
	// policy evaluation and is unconditional — a policy cannot disable it
	// because the agent could just edit the policy. A write-capable tool
	// call targeting a protected prefix is denied here, audited via the
	// same boundary-deny path as rate-limit/fail-closed, and never reaches
	// the engine.
	if len(p.protectPaths) > 0 {
		if violated, reason := engine.ViolatesProtectedPaths(&env, p.protectPaths); violated {
			receipt := p.emitBoundaryDeny(&env, reason, mode, policySetHash)
			p.denyCount.Add(1)
			writeJSON(w, http.StatusForbidden, addDecisionReceipt(map[string]any{
				"decision":        "denied",
				"action_taken":    "denied",
				"decision_reason": reason,
				"effective_mode":  mode,
			}, receipt))
			return
		}
	}

	// Velocity injection. Compute the trailing 1h/24h monetary window
	// for this key and, unless the caller already supplied an
	// agent_velocity block (authoritative ledger), inject the aggregates
	// INCLUDING this prospective call so a `monetary_sum_1h > cap` rule
	// fires on the call that crosses the line. We record the call into
	// the window only if the final decision lets it proceed (below), so
	// denied attempts never inflate the window.
	var velWindow *velocityWindow
	var velAmount float64
	var velHasAmount bool
	var velNow time.Time
	if p.velocity != nil {
		// Velocity is a security control against an agent that CONTROLS the
		// envelope. env.Timestamp is client-supplied, so aggregating on it
		// would let an attacker spread fragmented calls across fake hours and
		// dodge the 1h window entirely. Use trusted SERVER wall-clock instead;
		// env.Timestamp still stamps the audit trace (what the client claimed).
		velNow = time.Now().UTC()
		velWindow = p.velocity.windowFor(velocityKey(&env, p.velocityKeyBy))
		if amt, aErr := env.Amount(); aErr == nil && amt > 0 {
			velAmount, velHasAmount = amt, true
		}
		if env.Context.Verified.AgentVelocity == nil {
			s1, c1, s24, c24 := velWindow.aggregate(velNow)
			pCount := 0
			if velHasAmount {
				pCount = 1
			}
			env.Context.Verified.AgentVelocity = &domain.AgentVelocityContext{
				MonetarySum1h:    s1 + velAmount,
				MonetaryCount1h:  c1 + pCount,
				MonetarySum24h:   s24 + velAmount,
				MonetaryCount24h: c24 + pCount,
			}
		}
	}

	if len(policies) == 0 && p.failClosed {
		reason := "no policies loaded; fail-closed engaged"
		receipt := p.emitBoundaryDeny(&env, reason, mode, policySetHash)
		p.failClosedCount.Add(1)
		p.denyCount.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, addDecisionReceipt(map[string]any{
			"decision":        "denied",
			"action_taken":    "denied",
			"decision_reason": reason,
			"effective_mode":  mode,
		}, receipt))
		return
	}

	// safeEvaluate recovers a panic inside the deterministic engine (a bug
	// in the engine or a malformed policy that slipped past validation) and
	// turns it into an error instead of letting it propagate. Before this,
	// a per-request evaluator panic had NO recovery at all: it unwound out
	// of the handler into net/http's per-connection recover(), which just
	// closes the connection — no response, no audit trace, no counter. That
	// is worse than fail-open (there's at least a record when the engine
	// runs to completion) and directly contradicts -fail-closed's promise.
	//
	// Deliberately NOT gated behind -fail-closed the way "no policies
	// loaded" and "audit append failed" are: those are well-defined,
	// intentional configuration states an operator can reason about and
	// choose to allow through. A mid-evaluation panic isn't a state, it's a
	// crash — there is no principled decision to fall back to, so
	// fabricating an "allowed" result to honor -fail-closed=false would
	// paper over a real defect with a decision we have no evidence for.
	// Always deny; always audit; always count. This is stricter than
	// -fail-closed=false's stated posture, and that's intentional.
	result, evalErr := p.safeEvaluate(&env, policies, mode)
	if evalErr != nil {
		reason := fmt.Sprintf("policy evaluator error; failing closed (unconditional — see safeEvaluate): %v", evalErr)
		receipt := p.emitBoundaryDeny(&env, reason, mode, policySetHash)
		p.failClosedCount.Add(1)
		p.denyCount.Add(1)
		writeJSON(w, http.StatusInternalServerError, addDecisionReceipt(map[string]any{
			"decision":        "denied",
			"action_taken":    "denied",
			"decision_reason": reason,
			"effective_mode":  mode,
		}, receipt))
		return
	}

	// Tool-name spoof guard. When -unknown-tools-deny is set, any
	// envelope whose tool_name is not declared in scope.tool_names of
	// some loaded ENFORCEMENT policy is denied — even if a policy
	// happened to match via tool_groups. This closes the family of
	// variant names (DROP_TABLE, drop_tables, drop_table_v2).
	if p.unknownToolsDeny && !engine.ToolNameKnown(env.ToolName, policies) {
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
	provenanceErr := p.stampTraceProvenance(&trace, policySetHash)
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
	auditErr := provenanceErr
	if auditErr == nil {
		auditErr = p.appendTrace(&trace)
	}
	var receipt *audit.DecisionReceipt
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
	} else {
		receipt = receiptForAppendedTrace(&trace)
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

	// Record this monetary action into its velocity window only when the
	// call actually proceeds (allow or flag). Denied and escalated calls
	// did not execute, so counting them would let a rejected attempt
	// inflate the window and deny the next legitimate call.
	if velWindow != nil && velHasAmount &&
		(result.Decision == domain.DecisionAllowed || result.Decision == domain.DecisionFlagged) {
		velWindow.record(velNow, velAmount)
	}

	if result.Decision == domain.DecisionEscalated {
		writeJSON(w, http.StatusAccepted, addDecisionReceipt(map[string]any{
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
		}, receipt))
		return
	}

	writeJSON(w, http.StatusOK, evaluationResponse{EvaluationResult: result, DecisionReceipt: receipt})
}

// safeEvaluate calls the engine and recovers a panic into an error instead
// of letting it unwind out of the HTTP handler. Mirrors evalHook's recover
// pattern in cmd/tg/hook.go — the same engine backs both entry points, so
// both need the same guarantee that a bug in the engine can never silently
// skip the audit trail or crash the caller's connection.
func (p *proxy) safeEvaluate(env *domain.ActionEnvelope, policies []domain.Policy, mode domain.PolicyMode) (*domain.EvaluationResult, error) {
	return recoverEvaluation(func() *domain.EvaluationResult {
		return p.eval.Evaluate(env, policies, mode)
	})
}

// recoverEvaluation runs fn and turns a panic into an error return instead
// of letting it propagate. Factored out from safeEvaluate as a pure
// function (no *proxy dependency) so the recover behavior itself is
// directly unit-testable with an artificial panicking closure — the real
// engine has no known reliable panic trigger to exercise this against, and
// manufacturing one would either be flaky or require deliberately breaking
// the engine just to prove a test fails; testing the mechanism in isolation
// is the honest way to cover it.
func recoverEvaluation(fn func() *domain.EvaluationResult) (result *domain.EvaluationResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("engine panic: %v", r)
		}
	}()
	return fn(), nil
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
