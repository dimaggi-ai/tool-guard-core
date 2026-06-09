package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// mockChainStore implements ChainStore for testing.
type mockChainStore struct {
	tracesBySession map[string][]*domain.DecisionTrace
	tracesByID      map[string]*domain.DecisionTrace
}

func newMockChainStore() *mockChainStore {
	return &mockChainStore{
		tracesBySession: make(map[string][]*domain.DecisionTrace),
		tracesByID:      make(map[string]*domain.DecisionTrace),
	}
}

func (m *mockChainStore) GetTracesBySession(_ context.Context, sessionID string) ([]*domain.DecisionTrace, error) {
	traces, ok := m.tracesBySession[sessionID]
	if !ok {
		return nil, nil
	}
	return traces, nil
}

func (m *mockChainStore) GetTraceUnscoped(_ context.Context, traceID string) (*domain.DecisionTrace, error) {
	trace, ok := m.tracesByID[traceID]
	if !ok {
		return nil, fmt.Errorf("trace not found")
	}
	return trace, nil
}

func (m *mockChainStore) addTrace(sessionID string, trace *domain.DecisionTrace) {
	m.tracesBySession[sessionID] = append(m.tracesBySession[sessionID], trace)
	m.tracesByID[trace.TraceID] = trace
}

// buildMockChain builds a valid chain of n traces for a session.
func buildMockChain(store *mockChainStore, sessionID string, n int) []*domain.DecisionTrace {
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	previousHash := ""
	var traces []*domain.DecisionTrace

	for i := 0; i < n; i++ {
		traceID := fmt.Sprintf("trace-%s-%03d", sessionID, i)
		envID := fmt.Sprintf("env-%s-%03d", sessionID, i)
		timestamp := ts.Add(time.Duration(i) * time.Second)

		trace := &domain.DecisionTrace{
			TraceID:           traceID,
			EnvelopeID:        envID,
			SessionID:         sessionID,
			Decision:          domain.DecisionAllowed,
			ActionTaken:       domain.ActionAllowed,
			Timestamp:         timestamp,
			PreviousTraceHash: previousHash,
		}
		hash, err := ComputeCanonicalTraceHash(trace)
		if err != nil {
			panic("buildMockChain: " + err.Error())
		}
		trace.TraceHash = hash
		store.addTrace(sessionID, trace)
		previousHash = hash
		traces = append(traces, trace)
	}
	return traces
}

func TestChainVerifier_ValidSession(t *testing.T) {
	store := newMockChainStore()
	buildMockChain(store, "sess-001", 5)
	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySession(context.Background(), "sess-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid chain, got errors: %+v", result.Errors)
	}
	if result.TracesCount != 5 {
		t.Errorf("expected 5 traces, got %d", result.TracesCount)
	}
}

func TestChainVerifier_EmptySession(t *testing.T) {
	store := newMockChainStore()
	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySession(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Error("empty session should be valid")
	}
	if result.TracesCount != 0 {
		t.Errorf("expected 0 traces, got %d", result.TracesCount)
	}
}

func TestChainVerifier_TamperedHash(t *testing.T) {
	store := newMockChainStore()
	traces := buildMockChain(store, "sess-002", 3)

	// Tamper with middle trace's hash
	traces[1].TraceHash = "sha256:tampered"

	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySession(context.Background(), "sess-002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("should detect tampered hash")
	}
	if len(result.Errors) == 0 {
		t.Fatal("should have errors")
	}

	// Should have a hash mismatch error on index 1
	foundMismatch := false
	for _, e := range result.Errors {
		if e.Index == 1 && e.Message == "trace hash mismatch" {
			foundMismatch = true
		}
	}
	if !foundMismatch {
		t.Error("should report hash mismatch on tampered trace")
	}
}

func TestChainVerifier_BrokenChainLink(t *testing.T) {
	store := newMockChainStore()
	traces := buildMockChain(store, "sess-003", 3)

	// Break chain link on trace 2
	traces[2].PreviousTraceHash = "sha256:wrong_previous"

	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySession(context.Background(), "sess-003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("should detect broken chain link")
	}

	foundChainBreak := false
	for _, e := range result.Errors {
		if e.Index == 2 && e.Message == "chain link broken: previous_trace_hash mismatch" {
			foundChainBreak = true
		}
	}
	if !foundChainBreak {
		t.Error("should report chain link broken error")
	}
}

func TestChainVerifier_VerifySingleTrace(t *testing.T) {
	store := newMockChainStore()
	traces := buildMockChain(store, "sess-004", 1)

	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySingleTrace(context.Background(), traces[0].TraceID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("single valid trace should verify, got errors: %+v", result.Errors)
	}
	if result.TracesCount != 1 {
		t.Errorf("expected 1 trace, got %d", result.TracesCount)
	}
}

func TestChainVerifier_VerifySingleTrace_Tampered(t *testing.T) {
	store := newMockChainStore()
	traces := buildMockChain(store, "sess-005", 1)

	// Tamper
	traces[0].TraceHash = "sha256:bad"

	verifier := NewChainVerifier(store)

	result, err := verifier.VerifySingleTrace(context.Background(), traces[0].TraceID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("tampered trace should not verify")
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestChainVerifier_VerifySingleTrace_NotFound(t *testing.T) {
	store := newMockChainStore()
	verifier := NewChainVerifier(store)

	_, err := verifier.VerifySingleTrace(context.Background(), "nonexistent")
	if err == nil {
		t.Error("should return error for nonexistent trace")
	}
}
