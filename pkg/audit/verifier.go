package audit

import (
	"context"
	"fmt"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ChainVerifier verifies the integrity of a hash chain for a session.
type ChainVerifier struct {
	store ChainStore
}

// ChainStore defines the interface for reading traces for verification.
// These methods are unscoped (no org_id) because chain verification is an
// internal operation that runs after the handler has already verified access.
type ChainStore interface {
	GetTracesBySession(ctx context.Context, sessionID string) ([]*domain.DecisionTrace, error)
	GetTraceUnscoped(ctx context.Context, traceID string) (*domain.DecisionTrace, error)
}

// NewChainVerifier creates a new chain verifier.
func NewChainVerifier(store ChainStore) *ChainVerifier {
	return &ChainVerifier{store: store}
}

// VerificationResult contains the outcome of a chain verification.
type VerificationResult struct {
	Valid       bool          `json:"valid"`
	TracesCount int           `json:"traces_count"`
	Errors      []VerifyError `json:"errors,omitempty"`
}

// VerifyError describes a specific chain integrity failure.
type VerifyError struct {
	TraceID  string `json:"trace_id"`
	Index    int    `json:"index"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

// VerifySession verifies the hash chain for all traces in a session.
func (v *ChainVerifier) VerifySession(ctx context.Context, sessionID string) (*VerificationResult, error) {
	traces, err := v.store.GetTracesBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("fetch traces: %w", err)
	}

	result := &VerificationResult{
		Valid:       true,
		TracesCount: len(traces),
	}

	previousHash := ""
	for i, trace := range traces {
		// Recompute the canonical hash (covers every decision field).
		// Single-path verification: no legacy-hash fallback because
		// that would let an attacker forge decision_reason /
		// rule_results / amount / mode while keeping a legacy hash.
		expectedHash, err := ComputeCanonicalTraceHash(trace)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, VerifyError{
				TraceID:  trace.TraceID,
				Index:    i,
				Expected: "",
				Actual:   trace.TraceHash,
				Message:  fmt.Sprintf("canonical hash: %v", err),
			})
			previousHash = trace.TraceHash
			continue
		}

		if trace.TraceHash != expectedHash {
			result.Valid = false
			result.Errors = append(result.Errors, VerifyError{
				TraceID:  trace.TraceID,
				Index:    i,
				Expected: expectedHash,
				Actual:   trace.TraceHash,
				Message:  "trace hash mismatch",
			})
		}

		// Verify chain link
		if trace.PreviousTraceHash != previousHash {
			result.Valid = false
			result.Errors = append(result.Errors, VerifyError{
				TraceID:  trace.TraceID,
				Index:    i,
				Expected: previousHash,
				Actual:   trace.PreviousTraceHash,
				Message:  "chain link broken: previous_trace_hash mismatch",
			})
		}

		previousHash = trace.TraceHash
	}

	return result, nil
}

// VerifySingleTrace verifies a single trace's hash.
func (v *ChainVerifier) VerifySingleTrace(ctx context.Context, traceID string) (*VerificationResult, error) {
	trace, err := v.store.GetTraceUnscoped(ctx, traceID)
	if err != nil {
		return nil, fmt.Errorf("fetch trace: %w", err)
	}

	expectedHash, hashErr := ComputeCanonicalTraceHash(trace)
	if hashErr != nil {
		expectedHash = ""
	}
	result := &VerificationResult{
		Valid:       hashErr == nil && trace.TraceHash == expectedHash,
		TracesCount: 1,
	}

	if !result.Valid {
		result.Errors = append(result.Errors, VerifyError{
			TraceID:  trace.TraceID,
			Index:    0,
			Expected: expectedHash,
			Actual:   trace.TraceHash,
			Message:  "trace hash mismatch",
		})
	}

	return result, nil
}
