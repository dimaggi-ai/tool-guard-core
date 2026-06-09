// Canonical JSON serialiser for trace records.
//
// This is THE most safety-critical file in the evidence pack pipeline.
// If two versions of Tool Guard serialise the same DecisionTrace to
// different byte sequences, the audit chain breaks and every evidence
// pack becomes unverifiable.
//
// Rules (locked — do not change without bumping CanonicalTraceVersion):
//   1. Sorted struct field order is enforced by the canonicalTraceV1
//      shape below. Map[string]any is NEVER canonicalised here.
//   2. encoding/json with SetEscapeHTML(false) — Go's default escapes
//      <, >, & inside strings which would break byte-equality across
//      languages reading the chain.
//   3. No omitempty on hash-bearing fields. An auditor must distinguish
//      "field was empty" from "field was missing".
//   4. RFC3339Nano UTC for every timestamp.
//   5. Float numbers are emitted with %.6f truncation if non-integer.
//      DecisionTrace doesn't currently carry general floats; if any are
//      added, lock their precision in the v1 schema or bump the version.
//
// Versioning:
//   CanonicalTraceVersion is the version that the audit chain hashing
//   currently uses. If you EVER need to change the canonical shape,
//   create canonicalTraceV2 + add a switch on the version field of new
//   traces. Existing v1 packs must remain verifiable forever.
package audit

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// CanonicalTraceVersion is the schema version of the canonical encoder.
// Increment on any breaking change. The verifier reads the trace's
// `_canonical_v` field at the top of the canonical JSON to know which
// shape to expect.
const CanonicalTraceVersion = "v1"

// canonicalTraceV1 mirrors domain.DecisionTrace with explicit field order
// and no omitempty. The struct field order in Go is preserved by
// encoding/json, so this is our authoritative serialisation shape.
//
// IMPORTANT: only add fields at the END. Re-ordering breaks every
// previously generated audit chain.
//
// FLOATS: ALL float64 source fields are converted to integers
// (cents / microseconds / basis points) for byte determinism. Go's
// encoding/json emits floats with dynamic precision ("1.2" not
// "1.20000"), so cross-language and cross-version equality is not
// guaranteed. Fixing each one as an integer at canonicalisation
// removes the variability — a Python verifier reading the chain
// gets the same bytes as a Go verifier.
type canonicalTraceV1 struct {
	CanonicalV string `json:"_canonical_v"`

	// Identity
	TraceID    string `json:"trace_id"`
	Timestamp  string `json:"timestamp"` // RFC3339Nano UTC, never time.Time
	OrgID      string `json:"org_id"`
	EnvelopeID string `json:"envelope_id"`

	// Snapshot
	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"agent_version"`
	SessionID    string `json:"session_id"`
	TurnNumber   int    `json:"turn_number"`
	ToolName     string `json:"tool_name"`
	ToolGroup    string `json:"tool_group"`
	// Source domain.DecisionTrace.Amount is float64 dollars; pinned as
	// integer cents.
	AmountCents  int64  `json:"amount_cents"`

	// Evaluation
	Decision       string `json:"decision"`
	ActionTaken    string `json:"action_taken"`
	DecisionReason string `json:"decision_reason"`
	Mode           string `json:"mode"`

	// Rule eval
	PoliciesMatched int                      `json:"policies_matched"`
	RulesEvaluated  int                      `json:"rules_evaluated"`
	RulesTriggered  int                      `json:"rules_triggered"`
	RuleResults     []canonicalRuleResultV1  `json:"rule_results"`

	// Near-miss + escalation
	IsNearMiss   bool   `json:"is_near_miss"`
	EscalatedTo  string `json:"escalated_to"`

	// Chain
	TraceHash         string `json:"trace_hash"`
	PreviousTraceHash string `json:"previous_trace_hash"`
	SignedBy          string `json:"signed_by"`

	// Timing — pinned as integer microseconds. Source is
	// domain.DecisionTrace.EvaluationDurationMs (float64 millis).
	EvaluationDurationMicros int64 `json:"evaluation_duration_micros"`

	// Deep eval (Gemma 4 hybrid)
	DeepEval *canonicalDeepEvalV1 `json:"deep_eval"`
}

type canonicalRuleResultV1 struct {
	RuleID        string `json:"rule_id"`
	RuleName      string `json:"rule_name"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version"`
	Matched       bool   `json:"matched"`
	Effect        string `json:"effect"`
	Severity      string `json:"severity"`
}

type canonicalDeepEvalV1 struct {
	Status            string `json:"status"`
	Model             string `json:"model"`
	PromptTemplateVer string `json:"prompt_template_version"`
	PromptSHA256      string `json:"prompt_sha256"`
	// Confidences pinned as basis points (0-10000). Source is float64
	// in 0.0-1.0; multiplied by 10000 and rounded. Pinning eliminates
	// the "0.6 vs 0.60000000000001" determinism trap that Go float64
	// → JSON inflicts.
	ConfidenceThresholdBP int `json:"confidence_threshold_bp"`
	ReportedConfidenceBP  int `json:"reported_confidence_bp"`
	Decision              string `json:"decision"`
	Reasoning             string `json:"reasoning"`
	TokensIn              int    `json:"tokens_in"`
	TokensOut             int    `json:"tokens_out"`
	ElapsedMs             int64  `json:"elapsed_ms"`
	ErrClass              string `json:"error_class"`
	FailModeApplied       string `json:"fail_mode_applied"`
	DowngradeApplied      bool   `json:"downgrade_applied"`
}

// amountCentsCanonical converts a float dollar amount to integer
// cents in a way that is symmetric for negative values and total for
// all IEEE-754 inputs. Engine-level validation rejects negative and
// non-finite amounts upstream; this is defence in depth so a stray
// non-finite Amount (from a future code path that bypasses the
// envelope validator) cannot produce silently-identical hash output
// for distinct adversarial inputs.
func amountCentsCanonical(amount float64) int64 {
	switch {
	case math.IsNaN(amount):
		return -1
	case math.IsInf(amount, 1):
		return math.MaxInt64
	case math.IsInf(amount, -1):
		return math.MinInt64
	}
	// math.Round implements round-half-away-from-zero, which is
	// symmetric: -1.5 → -2, 1.5 → 2. The previous `+ 0.5` shortcut
	// rounded -1.5 → -1 (toward zero) which is not symmetric.
	return int64(math.Round(amount * 100))
}

// CanonicalTraceBytes returns the byte-exact canonical JSON for a trace.
// Used by both the audit chain hasher (per-event) and the evidence pack
// generator (one line per trace in audit_chain.jsonl). MUST be
// deterministic — same input always yields the same bytes.
func CanonicalTraceBytes(t *domain.DecisionTrace) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	c := canonicalTraceV1{
		CanonicalV: CanonicalTraceVersion,
		TraceID:    t.TraceID,
		Timestamp:  t.Timestamp.UTC().Format(time.RFC3339Nano),
		OrgID:      t.OrgID,
		EnvelopeID: t.EnvelopeID,

		AgentID:      t.AgentID,
		AgentVersion: t.AgentVersion,
		SessionID:    t.SessionID,
		TurnNumber:   t.TurnNumber,
		ToolName:     t.ToolName,
		ToolGroup:    t.ToolGroup,
		// Cents = round(Amount * 100). math.Round handles negative
		// values symmetrically (-1.5 → -2 not -1) and clamps the
		// IEEE-754 specials so NaN/+Inf/-Inf don't all collide on
		// the same int64 (which would let an adversary distinct
		// non-finite values serialise to byte-identical entries).
		AmountCents:  amountCentsCanonical(t.Amount),

		Decision:       string(t.Decision),
		ActionTaken:    string(t.ActionTaken),
		DecisionReason: t.DecisionReason,
		Mode:           string(t.Mode),

		PoliciesMatched: t.PoliciesMatched,
		RulesEvaluated:  t.RulesEvaluated,
		RulesTriggered:  t.RulesTriggered,

		IsNearMiss:  t.IsNearMiss,
		EscalatedTo: t.EscalatedTo,

		TraceHash:         t.TraceHash,
		PreviousTraceHash: t.PreviousTraceHash,
		SignedBy:          t.SignedBy,

		// Pin duration as integer microseconds (1 ms = 1000 µs).
		EvaluationDurationMicros: int64(t.EvaluationDurationMs*1000 + 0.5),
	}

	// Rule results: sorted by RuleID for deterministic order.
	c.RuleResults = make([]canonicalRuleResultV1, 0, len(t.RuleResults))
	for _, r := range t.RuleResults {
		c.RuleResults = append(c.RuleResults, canonicalRuleResultV1{
			RuleID:        r.RuleID,
			RuleName:      r.RuleName,
			PolicyID:      r.PolicyID,
			PolicyVersion: r.PolicyVersion,
			Matched:       r.Matched,
			Effect:        string(r.Effect),
			Severity:      r.Severity,
		})
	}
	sort.Slice(c.RuleResults, func(i, j int) bool {
		if c.RuleResults[i].RuleID != c.RuleResults[j].RuleID {
			return c.RuleResults[i].RuleID < c.RuleResults[j].RuleID
		}
		return c.RuleResults[i].PolicyID < c.RuleResults[j].PolicyID
	})

	if t.DeepEvalResult != nil {
		c.DeepEval = &canonicalDeepEvalV1{
			Status:                t.DeepEvalResult.Status,
			Model:                 t.DeepEvalResult.Model,
			PromptTemplateVer:     t.DeepEvalResult.PromptTemplateVer,
			PromptSHA256:          t.DeepEvalResult.PromptSHA256,
			ConfidenceThresholdBP: int(t.DeepEvalResult.ConfidenceThreshold*10000 + 0.5),
			ReportedConfidenceBP:  int(t.DeepEvalResult.ReportedConfidence*10000 + 0.5),
			Decision:              t.DeepEvalResult.Decision,
			Reasoning:             t.DeepEvalResult.Reasoning,
			TokensIn:              t.DeepEvalResult.TokensIn,
			TokensOut:             t.DeepEvalResult.TokensOut,
			ElapsedMs:             t.DeepEvalResult.ElapsedMs,
			ErrClass:              t.DeepEvalResult.ErrClass,
			FailModeApplied:       t.DeepEvalResult.FailModeApplied,
			DowngradeApplied:      t.DeepEvalResult.DowngradeApplied,
		}
	}

	// Encode with HTML escaping OFF — required for byte-stable output
	// across languages/tools reading the JSONL audit chain.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&c); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline — strip it for
	// hash stability. The JSONL writer adds its own '\n' between records.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}
