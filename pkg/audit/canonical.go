// Canonical JSON serialiser for trace records.
//
// This is THE most safety-critical file in the evidence pack pipeline.
// If two versions of Tool Guard serialise the same DecisionTrace to
// different byte sequences, the audit chain breaks and every evidence
// pack becomes unverifiable.
//
// Rules (locked — do not change without bumping CanonicalTraceVersion):
//  1. Sorted struct field order is enforced by the versioned canonicalTrace
//     shapes below. Map[string]any is NEVER canonicalised here.
//  2. encoding/json with SetEscapeHTML(false) — Go's default escapes
//     <, >, & inside strings which would break byte-equality across
//     languages reading the chain.
//  3. No omitempty on hash-bearing fields. An auditor must distinguish
//     "field was empty" from "field was missing".
//  4. RFC3339Nano UTC for every timestamp.
//  5. Float source fields use a version-locked integer representation: scaled
//     integers where precision is intentionally bounded, or IEEE-754 bits
//     where every evaluated float64 value is decision-relevant.
//
// Versioning:
//
//	CanonicalTraceVersion is the version that new audit records use. If you
//	EVER need to change the canonical shape, add a new immutable encoder and
//	extend the version switch. Existing versions must remain verifiable forever.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

const (
	canonicalTraceVersionV1 = "v1"
	canonicalTraceVersionV2 = "v2"
)

// CanonicalTraceVersion is the schema version stamped on newly written
// records. An absent DecisionTrace.CanonicalVersion means v1 so audit logs
// produced before the on-record version marker remain verifiable forever.
const CanonicalTraceVersion = canonicalTraceVersionV2

// effectiveCanonicalTraceVersion maps records written before the on-record
// version marker to v1. Keep this interpretation in one place: both canonical
// hashing and chain verification depend on the absence of _canonical_v meaning
// the immutable v1 projection.
func effectiveCanonicalTraceVersion(t *domain.DecisionTrace) string {
	if t == nil || t.CanonicalVersion == "" {
		return canonicalTraceVersionV1
	}
	return t.CanonicalVersion
}

func canonicalTraceVersionRank(version string) (int, bool) {
	switch version {
	case canonicalTraceVersionV1:
		return 1, true
	case canonicalTraceVersionV2:
		return 2, true
	default:
		return 0, false
	}
}

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
	AmountCents int64 `json:"amount_cents"`

	// Evaluation
	Decision       string `json:"decision"`
	ActionTaken    string `json:"action_taken"`
	DecisionReason string `json:"decision_reason"`
	Mode           string `json:"mode"`

	// Rule eval
	PoliciesMatched int                     `json:"policies_matched"`
	RulesEvaluated  int                     `json:"rules_evaluated"`
	RulesTriggered  int                     `json:"rules_triggered"`
	RuleResults     []canonicalRuleResultV1 `json:"rule_results"`

	// Near-miss + escalation
	IsNearMiss  bool   `json:"is_near_miss"`
	EscalatedTo string `json:"escalated_to"`

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
	ConfidenceThresholdBP int    `json:"confidence_threshold_bp"`
	ReportedConfidenceBP  int    `json:"reported_confidence_bp"`
	Decision              string `json:"decision"`
	Reasoning             string `json:"reasoning"`
	TokensIn              int    `json:"tokens_in"`
	TokensOut             int    `json:"tokens_out"`
	ElapsedMs             int64  `json:"elapsed_ms"`
	ErrClass              string `json:"error_class"`
	FailModeApplied       string `json:"fail_mode_applied"`
	DowngradeApplied      bool   `json:"downgrade_applied"`
}

// canonicalTraceV2 commits the action provenance introduced for mixed
// shadow/enforcement policy sets. v1 is intentionally left byte-for-byte
// unchanged; new writers stamp DecisionTrace.CanonicalVersion="v2", while
// records without that on-record marker continue through the v1 encoder.
type canonicalTraceV2 struct {
	CanonicalV string `json:"_canonical_v"`

	TraceID    string `json:"trace_id"`
	Timestamp  string `json:"timestamp"`
	OrgID      string `json:"org_id"`
	EnvelopeID string `json:"envelope_id"`

	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"agent_version"`
	SessionID    string `json:"session_id"`
	TurnNumber   int    `json:"turn_number"`
	ToolName     string `json:"tool_name"`
	ToolGroup    string `json:"tool_group"`
	// Exact IEEE-754 bits avoid cross-language decimal-format differences
	// without rounding decision-relevant sub-cent values.
	AmountBits        uint64 `json:"amount_bits"`
	AmountParseStatus string `json:"amount_parse_status"`

	Decision       string `json:"decision"`
	ActionTaken    string `json:"action_taken"`
	DecisionReason string `json:"decision_reason"`
	Mode           string `json:"mode"`

	PoliciesMatched        int                     `json:"policies_matched"`
	RulesEvaluated         int                     `json:"rules_evaluated"`
	RulesTriggered         int                     `json:"rules_triggered"`
	RuleResults            []canonicalRuleResultV2 `json:"rule_results"`
	AppliedRuleResults     []canonicalRuleResultV2 `json:"applied_rule_results"`
	PrimaryCitation        *canonicalCitationV2    `json:"primary_citation"`
	AppliedPrimaryCitation *canonicalCitationV2    `json:"applied_primary_citation"`
	SuggestedResponse      string                  `json:"suggested_response"`

	IsNearMiss  bool   `json:"is_near_miss"`
	EscalatedTo string `json:"escalated_to"`

	TraceHash         string `json:"trace_hash"`
	PreviousTraceHash string `json:"previous_trace_hash"`
	SignedBy          string `json:"signed_by"`

	EvaluationDurationMicros int64                `json:"evaluation_duration_micros"`
	DeepEval                 *canonicalDeepEvalV2 `json:"deep_eval"`

	// Record provenance is appended to the v2 projection and therefore covered
	// by the trace hash together with decision and applied-action provenance.
	EngineVersion string `json:"engine_version"`
	PolicySetHash string `json:"policy_set_hash"`
	SchemaVersion string `json:"schema_version"`
}

type canonicalRuleResultV2 struct {
	RuleID        string              `json:"rule_id"`
	RuleName      string              `json:"rule_name"`
	PolicyID      string              `json:"policy_id"`
	PolicyVersion int                 `json:"policy_version"`
	Matched       bool                `json:"matched"`
	Effect        string              `json:"effect"`
	Severity      string              `json:"severity"`
	Citation      canonicalCitationV2 `json:"citation"`
	Details       string              `json:"details"`
}

type canonicalCitationV2 struct {
	DocumentID    string `json:"document_id"`
	DocumentTitle string `json:"document_title"`
	Section       string `json:"section"`
	Page          int    `json:"page"`
	Line          int    `json:"line"`
	Excerpt       string `json:"excerpt"`
}

type canonicalDeepEvalV2 struct {
	Status                string `json:"status"`
	Model                 string `json:"model"`
	PromptTemplateVer     string `json:"prompt_template_version"`
	PromptSHA256          string `json:"prompt_sha256"`
	ConfidenceThresholdBP int    `json:"confidence_threshold_bp"`
	ReportedConfidenceBP  int    `json:"reported_confidence_bp"`
	Decision              string `json:"decision"`
	Reasoning             string `json:"reasoning"`
	TokensIn              int    `json:"tokens_in"`
	TokensOut             int    `json:"tokens_out"`
	ElapsedMs             int64  `json:"elapsed_ms"`
	ErrClass              string `json:"error_class"`
	FailModeApplied       string `json:"fail_mode_applied"`
	DowngradeApplied      bool   `json:"downgrade_applied"`
	FailClosedTriggered   bool   `json:"fail_closed_triggered"`
	TemperatureMicros     int64  `json:"temperature_micros"`
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
	version := effectiveCanonicalTraceVersion(t)
	switch version {
	case canonicalTraceVersionV1:
		if len(t.AppliedRuleResults) > 0 || t.AppliedPrimaryCitation != nil || t.AmountParseStatus != "" ||
			t.EngineVersion != "" || t.PolicySetHash != "" || t.SchemaVersion != "" {
			return nil, fmt.Errorf("v1 trace contains v2-only provenance fields")
		}
		return canonicalTraceBytesV1(t)
	case canonicalTraceVersionV2:
		if t.SchemaVersion != canonicalTraceVersionV2 {
			return nil, fmt.Errorf("canonical v2 trace requires schema_version %q", canonicalTraceVersionV2)
		}
		if err := validateTraceProvenance(t); err != nil {
			return nil, err
		}
		return canonicalTraceBytesV2(t)
	default:
		return nil, fmt.Errorf("unsupported canonical trace version %q", version)
	}
}

func canonicalTraceBytesV1(t *domain.DecisionTrace) ([]byte, error) {
	c := canonicalTraceV1{
		CanonicalV: canonicalTraceVersionV1,
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
		AmountCents: amountCentsCanonical(t.Amount),

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

	return encodeCanonical(&c)
}

func canonicalTraceBytesV2(t *domain.DecisionTrace) ([]byte, error) {
	c := canonicalTraceV2{
		CanonicalV: canonicalTraceVersionV2,
		TraceID:    t.TraceID,
		Timestamp:  t.Timestamp.UTC().Format(time.RFC3339Nano),
		OrgID:      t.OrgID,
		EnvelopeID: t.EnvelopeID,

		AgentID:           t.AgentID,
		AgentVersion:      t.AgentVersion,
		SessionID:         t.SessionID,
		TurnNumber:        t.TurnNumber,
		ToolName:          t.ToolName,
		ToolGroup:         t.ToolGroup,
		AmountBits:        math.Float64bits(t.Amount),
		AmountParseStatus: t.AmountParseStatus,

		Decision:       string(t.Decision),
		ActionTaken:    string(t.ActionTaken),
		DecisionReason: t.DecisionReason,
		Mode:           string(t.Mode),

		PoliciesMatched:        t.PoliciesMatched,
		RulesEvaluated:         t.RulesEvaluated,
		RulesTriggered:         t.RulesTriggered,
		PrimaryCitation:        canonicalCitationV2Ptr(t.PrimaryCitation),
		AppliedPrimaryCitation: canonicalCitationV2Ptr(t.AppliedPrimaryCitation),
		SuggestedResponse:      t.SuggestedResponse,

		IsNearMiss:  t.IsNearMiss,
		EscalatedTo: t.EscalatedTo,

		TraceHash:         t.TraceHash,
		PreviousTraceHash: t.PreviousTraceHash,
		SignedBy:          t.SignedBy,

		EvaluationDurationMicros: int64(t.EvaluationDurationMs*1000 + 0.5),

		EngineVersion: t.EngineVersion,
		PolicySetHash: t.PolicySetHash,
		SchemaVersion: t.SchemaVersion,
	}

	c.RuleResults = canonicalRuleResultsV2(t.RuleResults)
	c.AppliedRuleResults = canonicalRuleResultsV2(t.AppliedRuleResults)
	if t.DeepEvalResult != nil {
		c.DeepEval = canonicalDeepEvalRecordV2(t.DeepEvalResult)
	}
	return encodeCanonical(&c)
}

func canonicalRuleResultsV2(results []domain.RuleResult) []canonicalRuleResultV2 {
	out := make([]canonicalRuleResultV2, 0, len(results))
	for _, r := range results {
		out = append(out, canonicalRuleResultV2{
			RuleID:        r.RuleID,
			RuleName:      r.RuleName,
			PolicyID:      r.PolicyID,
			PolicyVersion: r.PolicyVersion,
			Matched:       r.Matched,
			Effect:        string(r.Effect),
			Severity:      r.Severity,
			Citation:      canonicalCitationV2Value(r.Citation),
			Details:       r.Details,
		})
	}
	return out
}

func canonicalCitationV2Ptr(c *domain.Citation) *canonicalCitationV2 {
	if c == nil {
		return nil
	}
	value := canonicalCitationV2Value(*c)
	return &value
}

func canonicalCitationV2Value(c domain.Citation) canonicalCitationV2 {
	return canonicalCitationV2{
		DocumentID:    c.DocumentID,
		DocumentTitle: c.DocumentTitle,
		Section:       c.Section,
		Page:          c.Page,
		Line:          c.Line,
		Excerpt:       c.Excerpt,
	}
}

func canonicalDeepEvalRecordV2(record *domain.DeepEvalRecord) *canonicalDeepEvalV2 {
	return &canonicalDeepEvalV2{
		Status:                record.Status,
		Model:                 record.Model,
		PromptTemplateVer:     record.PromptTemplateVer,
		PromptSHA256:          record.PromptSHA256,
		ConfidenceThresholdBP: int(record.ConfidenceThreshold*10000 + 0.5),
		ReportedConfidenceBP:  int(record.ReportedConfidence*10000 + 0.5),
		Decision:              record.Decision,
		Reasoning:             record.Reasoning,
		TokensIn:              record.TokensIn,
		TokensOut:             record.TokensOut,
		ElapsedMs:             record.ElapsedMs,
		ErrClass:              record.ErrClass,
		FailModeApplied:       record.FailModeApplied,
		DowngradeApplied:      record.DowngradeApplied,
		FailClosedTriggered:   record.FailClosedTriggered,
		TemperatureMicros:     int64(math.Round(record.Temperature * 1_000_000)),
	}
}

func encodeCanonical(value any) ([]byte, error) {
	// Encode with HTML escaping OFF — required for byte-stable output
	// across languages/tools reading the JSONL audit chain.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
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
