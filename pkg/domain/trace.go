package domain

import (
	"encoding/json"
	"time"
)

// Decision represents the overall evaluation outcome.
type Decision string

const (
	DecisionAllowed   Decision = "allowed"
	DecisionDenied    Decision = "denied"
	DecisionEscalated Decision = "escalated"
	DecisionFlagged   Decision = "flagged"
)

// ActionTaken represents what actually happened (differs from decision in shadow mode).
type ActionTaken string

const (
	ActionAllowed       ActionTaken = "allowed"
	ActionDenied        ActionTaken = "denied"
	ActionEscalated     ActionTaken = "escalated"
	ActionFlagged       ActionTaken = "flagged"
	ActionAllowedShadow ActionTaken = "allowed_shadow" // Shadow mode: would have denied/escalated
)

// DecisionTrace is the immutable, tamper-evident audit record for every evaluation.
// Spec: 03_Decision_Trace_v0
type DecisionTrace struct {
	// Identity
	TraceID    string    `json:"trace_id"`
	Timestamp  time.Time `json:"timestamp"`
	OrgID      string    `json:"org_id"`
	EnvelopeID string    `json:"envelope_id"`

	// Snapshot of the envelope (with redacted params only)
	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"agent_version,omitempty"`
	SessionID    string `json:"session_id"`
	TurnNumber   int    `json:"turn_number,omitempty"`
	ToolName     string `json:"tool_name"`
	ToolGroup    string `json:"tool_group"`
	Amount       float64 `json:"amount,omitempty"`

	// Evaluation result
	Decision       Decision    `json:"decision"`
	ActionTaken    ActionTaken `json:"action_taken"`
	DecisionReason string      `json:"decision_reason,omitempty"` // Human-readable explanation
	Mode           PolicyMode  `json:"mode"`

	// Rule evaluation details
	PoliciesMatched int          `json:"policies_matched"`
	RulesEvaluated  int          `json:"rules_evaluated"`
	RulesTriggered  int          `json:"rules_triggered"`
	RuleResults     []RuleResult `json:"rule_results"`

	// Primary citation (the most severe triggered rule's citation)
	PrimaryCitation *Citation `json:"primary_citation,omitempty"`

	// Suggested response (persisted for audit trail)
	SuggestedResponse string `json:"suggested_response,omitempty"`

	// Near-miss flag
	IsNearMiss bool `json:"is_near_miss"`

	// Escalation tracking
	EscalationID *string    `json:"escalation_id,omitempty"`
	EscalatedTo  string     `json:"escalated_to,omitempty"`
	EscalatedAt  *time.Time `json:"escalated_at,omitempty"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	Resolution   string     `json:"resolution,omitempty"` // approved, denied, timeout

	// Integrity (hash chain)
	TraceHash         string `json:"trace_hash"`
	PreviousTraceHash string `json:"previous_trace_hash,omitempty"`
	SignedBy          string `json:"signed_by,omitempty"` // Proxy instance ID

	// Redacted parameters
	ParametersRedacted []byte `json:"parameters_redacted,omitempty"`

	// Context snapshot (self-contained trace for audit)
	ContextSnapshot json.RawMessage `json:"context_snapshot,omitempty"`

	// Timing
	EvaluationDurationMs float64 `json:"evaluation_duration_ms"`

	// Agent LLM usage on the upstream model call this tool call was part of.
	// Populated when the proxy can read usage headers from the agent's LLM
	// response (e.g. via the agent SDK / MCP bridge). Distinct from
	// DeepEvalResult.TokensIn/Out, which records Tool Guard's OWN internal
	// hybrid-eval model usage. Powers the token-spend velocity rules.
	AgentTokensIn    int     `json:"agent_tokens_in,omitempty"`
	AgentTokensOut   int     `json:"agent_tokens_out,omitempty"`
	AgentLLMCostUSD  float64 `json:"agent_llm_cost_usd,omitempty"`

	// DeepEvalResult, when non-nil, records the Gemma 4 hybrid-eval outcome
	// that ran alongside the deterministic rule match. Captured here so the
	// audit chain (and the eventual evidence pack) can prove the AI second
	// opinion happened, what it returned, and how the engine combined it
	// with the deterministic result. Always populated for policies that
	// declared `DeepEvaluation`; absent for pure-deterministic policies.
	DeepEvalResult *DeepEvalRecord `json:"deep_eval_result,omitempty"`
}

// DeepEvalRecord is the per-trace projection of gemma.Result that gets
// hashed into the audit chain. It excludes the live elapsed Duration type
// (Go-only) and only carries the wire-stable fields.
//
// Adding fields here MUST bump the canonical-trace version (see
// pkg/audit/canonical.go) so existing evidence packs remain verifiable.
type DeepEvalRecord struct {
	Status               string  `json:"status"`
	Model                string  `json:"model"`
	PromptTemplateVer    string  `json:"prompt_template_version"`
	PromptSHA256         string  `json:"prompt_sha256"`
	ConfidenceThreshold  float64 `json:"confidence_threshold,omitempty"`
	ReportedConfidence   float64 `json:"reported_confidence,omitempty"`
	Decision             string  `json:"decision,omitempty"`
	Reasoning            string  `json:"reasoning,omitempty"`
	TokensIn             int     `json:"tokens_in,omitempty"`
	TokensOut            int     `json:"tokens_out,omitempty"`
	ElapsedMs            int64   `json:"elapsed_ms"`
	ErrClass             string  `json:"error_class,omitempty"`
	FailModeApplied      string  `json:"fail_mode_applied,omitempty"` // "closed" or "open"
	DowngradeApplied     bool    `json:"downgrade_applied,omitempty"` // true if the engine downgraded the decision due to deep eval
	// FailClosedTriggered records that Gemma's failure WOULD have caused
	// a downgrade-to-DENY under fail-closed semantics, regardless of
	// whether the final decision changed (e.g. it was already DENY).
	// Lets auditors track Gemma reliability separately from outcome.
	FailClosedTriggered  bool    `json:"fail_closed_triggered,omitempty"`
	// Temperature used in the Gemma call, recorded for reproducibility.
	Temperature          float64 `json:"temperature,omitempty"`
}

// ContextSnapshotData is the structured context stored in the trace.
type ContextSnapshotData struct {
	CustomerTier     string  `json:"customer_tier,omitempty"`
	CumulativeAmount float64 `json:"cumulative_amount,omitempty"`
	ActionsInSession int     `json:"actions_in_session,omitempty"`
	Rolling24hTotal  float64 `json:"rolling_24h_total,omitempty"`
	Rolling24hCount  int     `json:"rolling_24h_count,omitempty"`
	BudgetRemaining       float64 `json:"budget_remaining,omitempty"`
	BudgetUsedToday       float64 `json:"budget_used_today,omitempty"`
	ContentRisk           string  `json:"content_risk,omitempty"`
	ContentClassifierTier string  `json:"content_classifier_tier,omitempty"`
	CounterAgentRisk      string  `json:"counter_agent_risk,omitempty"`
}

// RuleResult records the outcome of evaluating a single rule.
type RuleResult struct {
	RuleID        string `json:"rule_id"`
	RuleName      string `json:"rule_name"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version,omitempty"`
	Matched       bool   `json:"matched"`
	Effect        Effect `json:"effect"`
	Severity      string `json:"severity,omitempty"`
	Citation      Citation `json:"citation"`
	Details       string   `json:"details,omitempty"`
}

// EvaluationResult is the output of the policy engine.
type EvaluationResult struct {
	Decision          Decision     `json:"decision"`
	ActionTaken       ActionTaken  `json:"action_taken"`
	DecisionReason    string       `json:"decision_reason,omitempty"`
	EffectiveMode     PolicyMode   `json:"effective_mode"`
	PoliciesMatched   int          `json:"policies_matched"`
	RulesEvaluated    int          `json:"rules_evaluated"`
	RulesTriggered    int          `json:"rules_triggered"`
	RuleResults       []RuleResult `json:"rule_results"`
	PrimaryCitation   *Citation    `json:"primary_citation,omitempty"`
	IsNearMiss        bool         `json:"is_near_miss"`
	SuggestedResponse string       `json:"suggested_response,omitempty"`
}
