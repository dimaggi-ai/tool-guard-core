package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func receiptTrace(t *testing.T) *domain.DecisionTrace {
	t.Helper()
	trace := goldenTrace()
	trace.TraceID = "trc-receipt"
	trace.Timestamp = time.Date(2026, 8, 25, 1, 2, 3, 4, time.UTC)
	trace.Decision = domain.DecisionDenied
	trace.ActionTaken = domain.ActionDenied
	trace.EngineVersion = "v0.8.0-test"
	trace.PolicySetHash = "sha256:" + strings.Repeat("a", 64)
	trace.SchemaVersion = CanonicalTraceVersion
	trace.TraceHash = ""
	hash, err := ComputeCanonicalTraceHash(trace)
	if err != nil {
		t.Fatalf("ComputeCanonicalTraceHash: %v", err)
	}
	trace.TraceHash = hash
	return trace
}

func TestNewDecisionReceiptCopiesPersistedFields(t *testing.T) {
	trace := receiptTrace(t)
	trace.SignedBy = "proxy-instance-7"
	trace.TraceHash = ""
	hash, err := ComputeCanonicalTraceHash(trace)
	if err != nil {
		t.Fatalf("ComputeCanonicalTraceHash with issuer: %v", err)
	}
	trace.TraceHash = hash
	receipt := NewDecisionReceipt(trace)
	if receipt == nil {
		t.Fatal("NewDecisionReceipt returned nil")
	}
	if receipt.ReceiptVersion != ReceiptVersion || receipt.TraceID != trace.TraceID || receipt.TraceHash != trace.TraceHash {
		t.Fatalf("identity/version fields do not match trace: %+v", receipt)
	}
	if receipt.HashAlgorithm != HashAlgorithmSHA256 || receipt.IntegrityModel != IntegrityModelHashChain {
		t.Fatalf("algorithm/model fields are wrong: %+v", receipt)
	}
	if receipt.CanonicalTraceVersion != CanonicalTraceVersion {
		t.Errorf("canonical_trace_version=%q, want %q", receipt.CanonicalTraceVersion, CanonicalTraceVersion)
	}
	if receipt.Decision != trace.Decision || receipt.ActionTaken != trace.ActionTaken || !receipt.Timestamp.Equal(trace.Timestamp) {
		t.Errorf("decision fields do not match trace: %+v", receipt)
	}
	if receipt.Issuer != trace.SignedBy {
		t.Errorf("issuer=%q, want %q", receipt.Issuer, trace.SignedBy)
	}
	wantURI := "urn:tool-guard:trace:" + CanonicalTraceVersion + ":" + trace.TraceHash
	if receipt.ReceiptURI != wantURI {
		t.Errorf("receipt_uri=%q, want %q", receipt.ReceiptURI, wantURI)
	}
}

func TestNewDecisionReceiptSupportsLegacyCanonicalVersion(t *testing.T) {
	trace := receiptTrace(t)
	trace.SchemaVersion = ""
	trace.EngineVersion = ""
	trace.PolicySetHash = ""
	trace.TraceHash = ""
	hash, err := ComputeCanonicalTraceHash(trace)
	if err != nil {
		t.Fatalf("ComputeCanonicalTraceHash legacy: %v", err)
	}
	trace.TraceHash = hash
	receipt := NewDecisionReceipt(trace)
	if receipt == nil || receipt.CanonicalTraceVersion != canonicalTraceVersionV1 {
		t.Fatalf("legacy receipt = %+v, want canonical version %q", receipt, canonicalTraceVersionV1)
	}
	wantURI := "urn:tool-guard:trace:v1:" + trace.TraceHash
	if receipt.ReceiptURI != wantURI {
		t.Errorf("legacy receipt_uri=%q, want %q", receipt.ReceiptURI, wantURI)
	}
}

func TestNewDecisionReceiptRejectsIncompleteOrMalformedTrace(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.DecisionTrace)
	}{
		{name: "nil trace"},
		{name: "missing trace id", mutate: func(trace *domain.DecisionTrace) { trace.TraceID = "" }},
		{name: "missing hash", mutate: func(trace *domain.DecisionTrace) { trace.TraceHash = "" }},
		{name: "wrong hash algorithm", mutate: func(trace *domain.DecisionTrace) { trace.TraceHash = "sha1:" + strings.Repeat("a", 64) }},
		{name: "short hash", mutate: func(trace *domain.DecisionTrace) { trace.TraceHash = "sha256:abcd" }},
		{name: "uppercase hash", mutate: func(trace *domain.DecisionTrace) { trace.TraceHash = "sha256:" + strings.Repeat("A", 64) }},
		{name: "well-formed but incorrect hash", mutate: func(trace *domain.DecisionTrace) { trace.TraceHash = "sha256:" + strings.Repeat("b", 64) }},
		{name: "unknown canonical version", mutate: func(trace *domain.DecisionTrace) { trace.SchemaVersion = "v99" }},
		{name: "missing timestamp", mutate: func(trace *domain.DecisionTrace) { trace.Timestamp = time.Time{} }},
		{name: "missing decision", mutate: func(trace *domain.DecisionTrace) { trace.Decision = "" }},
		{name: "missing action", mutate: func(trace *domain.DecisionTrace) { trace.ActionTaken = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.mutate == nil {
				if receipt := NewDecisionReceipt(nil); receipt != nil {
					t.Fatalf("nil trace produced receipt: %+v", receipt)
				}
				return
			}
			trace := receiptTrace(t)
			test.mutate(trace)
			if receipt := NewDecisionReceipt(trace); receipt != nil {
				t.Fatalf("invalid trace produced receipt: %+v", receipt)
			}
		})
	}
}

func TestNewDecisionReceiptDoesNotChangeCanonicalTrace(t *testing.T) {
	trace := receiptTrace(t)
	before, err := CanonicalTraceBytes(trace)
	if err != nil {
		t.Fatalf("CanonicalTraceBytes before: %v", err)
	}
	_ = NewDecisionReceipt(trace)
	after, err := CanonicalTraceBytes(trace)
	if err != nil {
		t.Fatalf("CanonicalTraceBytes after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("receipt construction changed canonical bytes\nbefore: %s\n after: %s", before, after)
	}
}
