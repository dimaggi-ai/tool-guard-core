package audit

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestStampProvenance(t *testing.T) {
	trace := &domain.DecisionTrace{}
	policyHash := "sha256:" + strings.Repeat("a", 64)
	if err := StampProvenance(trace, "v0.8.0", policyHash); err != nil {
		t.Fatalf("StampProvenance: %v", err)
	}
	if trace.EngineVersion != "v0.8.0" || trace.PolicySetHash != policyHash || trace.SchemaVersion != CanonicalTraceVersion {
		t.Fatalf("unexpected provenance: %+v", trace)
	}
}

func TestStampProvenanceRejectsIncompleteValues(t *testing.T) {
	validHash := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		name    string
		trace   *domain.DecisionTrace
		engine  string
		polHash string
	}{
		{name: "nil trace", engine: "v0.8.0", polHash: validHash},
		{name: "empty engine", trace: &domain.DecisionTrace{}, polHash: validHash},
		{name: "wrong algorithm", trace: &domain.DecisionTrace{}, engine: "v0.8.0", polHash: "sha1:" + strings.Repeat("a", 40)},
		{name: "short digest", trace: &domain.DecisionTrace{}, engine: "v0.8.0", polHash: "sha256:abcd"},
		{name: "uppercase digest", trace: &domain.DecisionTrace{}, engine: "v0.8.0", polHash: "sha256:" + strings.Repeat("A", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := StampProvenance(tt.trace, tt.engine, tt.polHash); err == nil {
				t.Fatal("StampProvenance() error = nil, want error")
			}
		})
	}
}
