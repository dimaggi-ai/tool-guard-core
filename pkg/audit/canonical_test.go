package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// canonical_test locks the v1 byte shape. If Go's encoding/json behaviour
// ever changes (escape rules, integer width, etc.) THESE tests break loud
// before any evidence pack ships with a drifted shape.
//
// To regenerate the golden bytes if you intentionally bump the schema:
//   1. Add a new canonicalTraceV<N> in canonical.go.
//   2. Preserve every older encoder and golden unchanged.
//   3. Bump CanonicalTraceVersion and add a new golden.

func goldenTrace() *domain.DecisionTrace {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-05-21T19:43:00Z")
	return &domain.DecisionTrace{
		TraceID:    "trace-test-001",
		Timestamp:  ts,
		OrgID:      "org-acme",
		EnvelopeID: "env-9001",

		AgentID:      "clinical-triage-agent-v1",
		AgentVersion: "1.4.0",
		SessionID:    "sess-abc",
		TurnNumber:   3,
		ToolName:     "patient_lookup",
		ToolGroup:    "phi-read",
		Amount:       0.0,

		Decision:       domain.DecisionDenied,
		ActionTaken:    domain.ActionDenied,
		DecisionReason: "Denied by: [r-001] pii-boundary (effect: deny)",
		Mode:           domain.PolicyModeEnforcement,

		PoliciesMatched: 2,
		RulesEvaluated:  4,
		RulesTriggered:  1,
		RuleResults: []domain.RuleResult{
			{
				RuleID:        "r-001",
				RuleName:      "block-phi-egress",
				PolicyID:      "pol-pii-boundary",
				PolicyVersion: 3,
				Matched:       true,
				Effect:        domain.EffectDeny,
				Severity:      "critical",
			},
		},

		IsNearMiss:  false,
		EscalatedTo: "",

		TraceHash:         "deadbeef",
		PreviousTraceHash: "cafebabe",
		SignedBy:          "proxy-1",

		EvaluationDurationMs: 12.4,

		DeepEvalResult: &domain.DeepEvalRecord{
			Status:              "ok",
			Model:               "gemma4:e4b",
			PromptTemplateVer:   "v1",
			PromptSHA256:        "abc123",
			ConfidenceThreshold: 0.6,
			ReportedConfidence:  0.91,
			Decision:            "deny",
			Reasoning:           "Patient has documented penicillin allergy; outbound looked clean to deterministic rule but model flagged a contraindication.",
			TokensIn:            420,
			TokensOut:           80,
			ElapsedMs:           870,
			ErrClass:            "",
			FailModeApplied:     "closed",
			DowngradeApplied:    true,
		},
	}
}

func goldenTraceV2() *domain.DecisionTrace {
	tr := goldenTrace()
	tr.CanonicalVersion = CanonicalTraceVersion
	tr.RuleResults[0].Citation = domain.Citation{
		DocumentID: "policy-handbook",
		Section:    "4.2",
		Page:       17,
		Line:       9,
		Excerpt:    "PHI export requires approval.",
	}
	tr.RuleResults[0].Details = "matched protected data class"
	tr.AppliedRuleResults = append([]domain.RuleResult(nil), tr.RuleResults[0])
	primary := tr.RuleResults[0].Citation
	tr.PrimaryCitation = &primary
	applied := primary
	tr.AppliedPrimaryCitation = &applied
	tr.SuggestedResponse = "Request supervisor approval."
	return tr
}

// wantCanonicalV1 is the byte-exact expected output of the canonical encoder.
// If this test fails, either:
//
//	(a) you changed the encoder shape intentionally — bump CanonicalTraceVersion
//	    and add a v2 (do NOT edit v1)
//	(b) Go's encoding/json changed escape rules — investigate before shipping
const wantCanonicalV1 = `{"_canonical_v":"v1","trace_id":"trace-test-001","timestamp":"2026-05-21T19:43:00Z","org_id":"org-acme","envelope_id":"env-9001","agent_id":"clinical-triage-agent-v1","agent_version":"1.4.0","session_id":"sess-abc","turn_number":3,"tool_name":"patient_lookup","tool_group":"phi-read","amount_cents":0,"decision":"denied","action_taken":"denied","decision_reason":"Denied by: [r-001] pii-boundary (effect: deny)","mode":"enforcement","policies_matched":2,"rules_evaluated":4,"rules_triggered":1,"rule_results":[{"rule_id":"r-001","rule_name":"block-phi-egress","policy_id":"pol-pii-boundary","policy_version":3,"matched":true,"effect":"deny","severity":"critical"}],"is_near_miss":false,"escalated_to":"","trace_hash":"deadbeef","previous_trace_hash":"cafebabe","signed_by":"proxy-1","evaluation_duration_micros":12400,"deep_eval":{"status":"ok","model":"gemma4:e4b","prompt_template_version":"v1","prompt_sha256":"abc123","confidence_threshold_bp":6000,"reported_confidence_bp":9100,"decision":"deny","reasoning":"Patient has documented penicillin allergy; outbound looked clean to deterministic rule but model flagged a contraindication.","tokens_in":420,"tokens_out":80,"elapsed_ms":870,"error_class":"","fail_mode_applied":"closed","downgrade_applied":true}}`

func TestCanonicalTraceBytes_Golden(t *testing.T) {
	got, err := CanonicalTraceBytes(goldenTrace())
	if err != nil {
		t.Fatalf("CanonicalTraceBytes: %v", err)
	}
	if string(got) != wantCanonicalV1 {
		t.Errorf("canonical bytes drift detected\n want: %s\n  got: %s", wantCanonicalV1, string(got))
	}
}

func TestCanonicalTraceBytes_NoHTMLEscape(t *testing.T) {
	// Inputs containing < > & must pass through literally — Go's default
	// json.Marshal would encode them as < etc. and break byte equality
	// across languages reading the chain.
	tr := goldenTrace()
	tr.DecisionReason = "User asked for <patient_name> & <ssn>"
	out, err := CanonicalTraceBytes(tr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Contains(out, []byte("<patient_name>")) {
		t.Errorf("HTML escape leaked — expected literal '<patient_name>' in output, got: %s", string(out))
	}
	// The literal 6-byte sequence < must NOT appear — that would mean
	// Go's HTML escape leaked through despite SetEscapeHTML(false). We
	// build the byte slice explicitly so the test source itself doesn't
	// accidentally describe the search-for as a literal '<' character.
	if bytes.Contains(out, []byte{'\\', 'u', '0', '0', '3', 'c'}) {
		t.Errorf("unwanted unicode escape sequence \\\\u003c found: %s", string(out))
	}
}

func TestCanonicalTraceBytes_RuleResultsSorted(t *testing.T) {
	// Rule results must always emit in sorted order regardless of input.
	tr := goldenTrace()
	tr.RuleResults = []domain.RuleResult{
		{RuleID: "z-99", PolicyID: "pol-late"},
		{RuleID: "a-01", PolicyID: "pol-early"},
		{RuleID: "m-50", PolicyID: "pol-mid"},
	}
	out, err := CanonicalTraceBytes(tr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	a := strings.Index(string(out), `"a-01"`)
	m := strings.Index(string(out), `"m-50"`)
	z := strings.Index(string(out), `"z-99"`)
	if a < 0 || m < 0 || z < 0 || a > m || m > z {
		t.Errorf("rule_results not sorted: a-01@%d m-50@%d z-99@%d", a, m, z)
	}
}

func TestCanonicalTraceBytes_ParsesAsValidJSON(t *testing.T) {
	out, err := CanonicalTraceBytes(goldenTrace())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v\n%s", err, string(out))
	}
	if parsed["_canonical_v"] != "v1" {
		t.Errorf("missing/wrong canonical version marker: %v", parsed["_canonical_v"])
	}
}

func TestCanonicalTraceBytes_V2Golden(t *testing.T) {
	got, err := CanonicalTraceBytes(goldenTraceV2())
	if err != nil {
		t.Fatalf("CanonicalTraceBytes v2: %v", err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(got))
	const wantSHA256 = "8848c5cd254d191e1d75b771c292d70123cca396db140671ee1d3b3bf9c40d68"
	if sum != wantSHA256 {
		t.Fatalf("canonical v2 bytes drifted: sha256=%s, want %s\nbytes=%s", sum, wantSHA256, got)
	}
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("canonical v2 output is invalid JSON: %v", err)
	}
	if parsed["_canonical_v"] != "v2" {
		t.Fatalf("canonical v2 marker = %v", parsed["_canonical_v"])
	}
}

func TestCanonicalTraceV2AppliedProvenanceTamperFailsVerification(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.DecisionTrace)
	}{
		{"applied effect", func(tr *domain.DecisionTrace) { tr.AppliedRuleResults[0].Effect = domain.EffectAllow }},
		{"applied rule citation", func(tr *domain.DecisionTrace) { tr.AppliedRuleResults[0].Citation.Excerpt = "forged" }},
		{"applied primary citation", func(tr *domain.DecisionTrace) { tr.AppliedPrimaryCitation.Excerpt = "forged" }},
		{"raw primary citation", func(tr *domain.DecisionTrace) { tr.PrimaryCitation.Excerpt = "forged" }},
		{"rule diagnostic", func(tr *domain.DecisionTrace) { tr.RuleResults[0].Details = "forged" }},
		{"deep fail-closed marker", func(tr *domain.DecisionTrace) { tr.DeepEvalResult.FailClosedTriggered = true }},
		{"deep temperature", func(tr *domain.DecisionTrace) { tr.DeepEvalResult.Temperature = 0.25 }},
		{"version downgrade", func(tr *domain.DecisionTrace) { tr.CanonicalVersion = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := goldenTraceV2()
			hash, err := ComputeCanonicalTraceHash(tr)
			if err != nil {
				t.Fatal(err)
			}
			tr.TraceHash = hash
			tt.mutate(tr)
			ok, err := VerifyCanonicalTraceHash(tr)
			if err == nil && ok {
				t.Fatal("verification accepted tampered v2 provenance")
			}
		})
	}
}

func TestCanonicalTraceVersionSelection(t *testing.T) {
	legacy := goldenTrace()
	legacy.AppliedRuleResults = []domain.RuleResult{{RuleID: "forged"}}
	if _, err := CanonicalTraceBytes(legacy); err == nil {
		t.Fatal("v1 trace with injected v2-only provenance must be rejected")
	}
	unknown := goldenTrace()
	unknown.CanonicalVersion = "v99"
	if _, err := CanonicalTraceBytes(unknown); err == nil {
		t.Fatal("unknown canonical version must be rejected")
	}
}
