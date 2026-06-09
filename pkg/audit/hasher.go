package audit

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ComputeTraceHash returns the SHA-256 hash of the 6-key identity
// tuple (trace_id, envelope_id, decision, action_taken, timestamp,
// previous_hash). This is the historical hasher — it's adequate to
// detect re-ordering and identity tampering but it does NOT cover
// rule_results, decision_reason, agent identity, or amount. An
// attacker with write access to the audit log could mutate those
// fields and the 6-field hash would still match.
//
// Use ComputeCanonicalTraceHash below for full integrity coverage.
// The OSS proxy and `tg verify` use the canonical hasher; this
// function is retained for cmd/example-chain (which generates the
// shipped sample chain) and existing test fixtures.
func ComputeTraceHash(traceID, envelopeID, decision, actionTaken string, timestamp time.Time, previousHash string) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		traceID,
		envelopeID,
		decision,
		actionTaken,
		timestamp.UTC().Format(time.RFC3339Nano),
		previousHash,
	)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("sha256:%x", hash)
}

// VerifyTraceHash verifies a 6-field hash. Legacy companion to
// ComputeTraceHash. New code uses VerifyCanonicalTraceHash.
func VerifyTraceHash(traceID, envelopeID, decision, actionTaken string, timestamp time.Time, previousHash, expectedHash string) bool {
	computed := ComputeTraceHash(traceID, envelopeID, decision, actionTaken, timestamp, previousHash)
	return computed == expectedHash
}

// ComputeCanonicalTraceHash returns sha256(CanonicalTraceBytes(t)).
// The hash covers EVERY field of the decision: agent identity, tool
// name and group, amount, decision, action, decision_reason, every
// rule result, the chain link, and the deep-eval result if any. This
// is the integrity commitment the README and CHANGELOG promise.
//
// The canonical encoder includes the schema version (_canonical_v)
// as the first hashed byte string, so a future v2 record replayed by
// a v1 verifier hashes the v1 encoder's "v1" against the stored
// "v2" — the explicit version check below produces a clearer error
// than the resulting raw hash mismatch.
//
// To compute the trace's own hash, set t.TraceHash to "" before
// calling — the canonical encoder will then emit "" for that field,
// matching what the verifier feeds when re-deriving the hash from a
// stored line.
func ComputeCanonicalTraceHash(t *domain.DecisionTrace) (string, error) {
	if t == nil {
		return "", fmt.Errorf("ComputeCanonicalTraceHash: nil trace")
	}
	saved := t.TraceHash
	t.TraceHash = ""
	b, err := CanonicalTraceBytes(t)
	t.TraceHash = saved
	if err != nil {
		return "", fmt.Errorf("canonical encode: %w", err)
	}
	hash := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", hash), nil
}

// VerifyCanonicalTraceHash recomputes the canonical hash for a trace
// and compares it to the value already on the trace. Returns true on
// match. Used by the offline replay verifier.
func VerifyCanonicalTraceHash(t *domain.DecisionTrace) (bool, error) {
	if t == nil {
		return false, fmt.Errorf("VerifyCanonicalTraceHash: nil trace")
	}
	expected := t.TraceHash
	computed, err := ComputeCanonicalTraceHash(t)
	if err != nil {
		return false, err
	}
	return expected == computed, nil
}
