package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

func TestEvaluateOmitsReceiptWithoutChangingDecisionWhenAuditAppendFails(t *testing.T) {
	auditFile, err := os.CreateTemp(t.TempDir(), "closed-audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := auditFile.Close(); err != nil {
		t.Fatal(err)
	}
	policyHash, err := policyload.PolicySetHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{
		policySetHash: policyHash,
		engineVersion: "v0.8.0-test",
		auditLog:      auditFile,
		defaultMode:   domain.PolicyModeEnforcement,
		failClosed:    false,
		maxJSONDepth:  32,
		auditSyncMode: "none",
		escalations:   newEscalationStore(),
		eval:          engine.NewEvaluator(),
	}

	request := httptest.NewRequest(http.MethodPost, "/evaluate", strings.NewReader(`{
        "envelope_id":"env-audit-failure",
        "timestamp":"2026-08-25T00:00:00Z",
        "agent_id":"agent",
        "session_id":"session",
        "org_id":"org",
        "tool_name":"read_record",
        "parameters":{}
    }`))
	recorder := httptest.NewRecorder()
	p.evaluate(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var decision domain.Decision
	if err := json.Unmarshal(response["decision"], &decision); err != nil {
		t.Fatal(err)
	}
	if decision != domain.DecisionAllowed {
		t.Fatalf("audit failure changed fail-open decision to %q", decision)
	}
	if _, exists := response["decision_receipt"]; exists {
		t.Fatalf("failed append emitted decision_receipt: %s", recorder.Body.String())
	}
	if p.auditFailureCount.Load() != 1 {
		t.Errorf("audit failure counter=%d, want 1", p.auditFailureCount.Load())
	}
}
